import os
import glob
import json
import uuid
import re
import numpy as np
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any

import chromadb
from chromadb.utils import embedding_functions
from chromadb.config import Settings
from rank_bm25 import BM25Okapi
from openai import OpenAI
from config import load_env_file

XML_DIR = "../../Data/Pnetlab/L2VPN/xml" 
QUESTIONS_PATH = "../../Data/Pnetlab/L2VPN/Dataset/L2VPN_dataset_20251129_001331.json"

load_env_file()


class XMLProcessor:
    def _remove_namespaces(self, tree):
        for elem in tree.iter():
            if '}' in elem.tag:
                elem.tag = elem.tag.split('}', 1)[1]
        return tree

    def parse_to_chunks(self, file_path: str) -> List[Dict[str, str]]:
        chunks = []
        try:
            tree = ET.parse(file_path)
            self._remove_namespaces(tree)
            root = tree.getroot()
            
            devices = root.findall(".//device")
            if not devices: return []

            for device in devices:
                name = device.findtext("name", "Unknown")
                config = device.find("config")
                if config is None: continue
                
                base_meta = {"source": os.path.basename(file_path), "device": name}

                # 1. System Info (Hostname)
                hostname = config.findtext(".//hostname", "Unknown")
                sys_text = f"Device: {name}, Hostname: {hostname}"
                chunks.append({"text": sys_text, "meta": {**base_meta, "type": "system"}})

                # 2. Interface Info
                for iface in config.findall(".//interface/*"):
                    if_name = iface.findtext("name")
                    ip_info = iface.find(".//address/primary/address")
                    ip = ip_info.text if ip_info is not None else "No IP"
                    desc = f"Device {name} has Interface {iface.tag} {if_name} configured with IP address {ip}"
                    chunks.append({"text": desc, "meta": {**base_meta, "type": "interface"}})

                # 3. BGP Info
                bgp = config.find(".//router/bgp")
                if bgp is not None:
                    asn = bgp.findtext("as-number") or bgp.findtext("id")
                    bgp_text = f"Device {name} is configured with BGP AS number {asn}. "
                    for neighbor in bgp.findall("neighbor"):
                        n_id = neighbor.findtext("id")
                        r_as = neighbor.findtext("remote-as")
                        bgp_text += f"It has BGP Neighbor {n_id} with Remote-AS {r_as}. "
                    chunks.append({"text": bgp_text, "meta": {**base_meta, "type": "bgp", "asn": asn or ""}})
                else:
                    chunks.append({"text": f"Device {name} has NO BGP configuration.", "meta": {**base_meta, "type": "bgp"}})

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
        return chunks


class HybridRetriever:
    def __init__(self, xml_dir: str, db_path: str = "./chroma_db"):
        self.xml_dir = xml_dir
        self.processor = XMLProcessor()
        
        # ChromaDB 설정
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedding_fn = embedding_functions.OpenAIEmbeddingFunction(
            api_key=os.getenv("OPENAI_API_KEY"),
            model_name="text-embedding-3-small"
        )
        self.collection = self.client.get_or_create_collection(
            name="network_hybrid", embedding_function=self.embedding_fn
        )

        # BM25용 인메모리 저장소
        self.bm25 = None
        self.doc_store = {} 
        self.corpus_ids = [] 

        self._build_indices()

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[\w\.-]+", text.lower())

    def _build_indices(self):
        existing_count = self.collection.count()
        if existing_count > 0:
            print(f"기존 DB 데이터 로드 중... ({existing_count} chunks)")
            results = self.collection.get()
            
            tokenized_corpus = []
            for i, doc_id in enumerate(results['ids']):
                text = results['documents'][i]
                self.doc_store[doc_id] = {"text": text, "meta": results['metadatas'][i]}
                self.corpus_ids.append(doc_id)
                tokenized_corpus.append(self._tokenize(text))
            
            self.bm25 = BM25Okapi(tokenized_corpus)
            print("BM25 & DPR 인덱스 준비 완료")
            return

        print("DB 구축 및 인덱싱 시작...")
        xml_files = glob.glob(os.path.join(self.xml_dir, "*.xml"))
        all_tokenized = []
        
        for fpath in xml_files:
            chunks = self.processor.parse_to_chunks(fpath)
            if not chunks: continue
            
            ids = [str(uuid.uuid4()) for _ in chunks]
            documents = [c['text'] for c in chunks]
            metadatas = [c['meta'] for c in chunks]

            self.collection.add(ids=ids, documents=documents, metadatas=metadatas)

            for doc_id, text, meta in zip(ids, documents, metadatas):
                self.doc_store[doc_id] = {"text": text, "meta": meta}
                self.corpus_ids.append(doc_id)
                all_tokenized.append(self._tokenize(text))

        if all_tokenized:
            self.bm25 = BM25Okapi(all_tokenized)
            print("인덱싱 완료")


    def search_hybrid(self, query: str, top_k: int = 10) -> str:
        dense_k = top_k * 2 
        d_results = self.collection.query(query_texts=[query], n_results=dense_k)
        d_ids = d_results['ids'][0] if d_results['ids'] else []
        
        tokenized_query = self._tokenize(query)
        s_ids = []
        if self.bm25:
            s_scores = self.bm25.get_scores(tokenized_query)
            top_n_indices = np.argsort(s_scores)[::-1][:dense_k]
            s_ids = [self.corpus_ids[i] for i in top_n_indices]

        rrf_score = {}
        k_const = 60
        
        for rank, doc_id in enumerate(d_ids):
            rrf_score[doc_id] = rrf_score.get(doc_id, 0) + (1 / (k_const + rank + 1))
        
        for rank, doc_id in enumerate(s_ids):
            rrf_score[doc_id] = rrf_score.get(doc_id, 0) + (1 / (k_const + rank + 1))

        sorted_ids = sorted(rrf_score.items(), key=lambda x: x[1], reverse=True)[:top_k]
        
        context_parts = []
        for rank, (doc_id, score) in enumerate(sorted_ids, 1):
            doc_info = self.doc_store.get(doc_id)
            if doc_info:
                src = doc_info['meta']['source']
                text = doc_info['text']
                context_parts.append(f"[Source: {src}]\n{text}")
        
        return "\n\n".join(context_parts)


def generate_answer(client: OpenAI, question: str, context: str):
    prompt = f"""
    당신은 네트워크 엔지니어링 전문가입니다.
    아래 [검색된 네트워크 설정]만을 근거로 [질문]에 답변하세요.
    
    규칙:
    1. 답변은 정확한 수치나 장비명을 포함해야 합니다.
    2. 정보가 충분하지 않으면 솔직하게 "제공된 문서(Context)만으로는 전체 정보를 알 수 없습니다"라고 말하세요.
    3. 추측하지 마세요.

    [검색된 네트워크 설정]
    {context}

    [질문]
    {question}
    """
    
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0
    )
    return response.choices[0].message.content




def main():
    if not os.getenv("OPENAI_API_KEY"):
        print("API 키 오류: .env 파일 확인 필요")
        return
    
    retriever = HybridRetriever(xml_dir=XML_DIR)
    client = OpenAI()

    print("\n Hybrid RAG 실행 중...\n")

    if not os.path.exists(QUESTIONS_PATH):
        print(f" JSON 파일을 찾을 수 없습니다: {QUESTIONS_PATH}")
        return

    with open(QUESTIONS_PATH, "r", encoding='utf-8') as f:
        data = json.load(f)
        
    if isinstance(data, list):
        questions = [item['question'] for item in data]
    else:
        items = data.get("train", data)
        questions = [item['question'] for item in items]
        
    # 테스트 실행 (처음 3개만)
    for i, q in enumerate(questions):
        print(f"Q{i+1}: {q}")
        if i >= 3: break 
        
        context = retriever.search_hybrid(q, top_k=10)
        print("검색된 문서입니다.", context)
        if not context:
            print(" 관련 문서를 찾지 못했습니다.")
        else:
            answer = generate_answer(client, q, context)
            print(f" 답변: {answer}")
        
        print("-" * 60)

if __name__ == "__main__":
    main()