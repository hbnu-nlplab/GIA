#!/usr/bin/env python3
"""
227개 세분화된 청크 파일들을 ChromaDB에 임베딩
진짜 RAG를 위한 스크립트
"""
import os
import glob
import chromadb
from pathlib import Path
import sys

# pipeline_v2 경로 추가
sys.path.append('Evaluation/pipeline_v2')
from rag_pipeline import HuggingFaceEmbedder
from config import CHROMADB_PATH, EMBEDDING_MODEL

def create_chunk_embeddings():
    print("🚀 진짜 RAG를 위한 청크 임베딩 시작!")
    
    # 1. 임베더 초기화
    print("📊 임베더 초기화 중...")
    embedder = HuggingFaceEmbedder()
    
    # 2. ChromaDB 클라이언트
    print(f"🗄️  ChromaDB 연결: {CHROMADB_PATH}")
    client = chromadb.PersistentClient(path=CHROMADB_PATH)
    
    # 3. 새 컬렉션 생성 (기존 있으면 삭제)
    collection_name = "network_chunks"  # 새 이름
    print(f"📁 컬렉션 생성: {collection_name}")
    
    try:
        # 기존 컬렉션이 있으면 삭제
        client.delete_collection(collection_name)
        print("   기존 컬렉션 삭제됨")
    except Exception:
        print("   기존 컬렉션 없음 (정상)")
    
    collection = client.create_collection(collection_name)
    
    # 4. 청크 파일들 수집
    chunk_dir = "Evaluation/xml_Embedding"
    txt_files = glob.glob(f"{chunk_dir}/*.txt")
    print(f"📄 발견된 청크 파일: {len(txt_files)}개")
    
    # 5. 배치 임베딩
    batch_size = 20
    ids = []
    documents = []
    metadatas = []
    
    for i, file_path in enumerate(txt_files):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 메타데이터 파싱
            filename = os.path.basename(file_path)
            
            # 파일명에서 정보 추출 (예: 41_sample9_bgp_neighbor.txt)
            parts = filename.replace('.txt', '').split('_')
            chunk_id = parts[0]
            device_name = parts[1] if len(parts) > 1 else 'unknown'
            section_type = '_'.join(parts[2:]) if len(parts) > 2 else 'unknown'
            
            ids.append(f"chunk_{i}")
            documents.append(content)
            metadatas.append({
                'filename': filename,
                'chunk_id': chunk_id,
                'device_name': device_name,
                'section_type': section_type,
                'file_path': file_path
            })
            
            # 배치 단위로 임베딩
            if len(documents) >= batch_size:
                print(f"   배치 {len(ids)//batch_size}: {len(documents)}개 임베딩 중...")
                embeddings = embedder.embed(documents)
                collection.add(
                    ids=ids,
                    documents=documents, 
                    embeddings=embeddings,
                    metadatas=metadatas
                )
                ids, documents, metadatas = [], [], []
                
        except Exception as e:
            print(f"❌ 파일 처리 실패 {filename}: {e}")
    
    # 남은 문서들 임베딩
    if documents:
        print(f"   마지막 배치: {len(documents)}개 임베딩 중...")
        embeddings = embedder.embed(documents)
        collection.add(
            ids=ids,
            documents=documents,
            embeddings=embeddings, 
            metadatas=metadatas
        )
    
    print(f"✅ 완료! 총 {collection.count()}개 청크 임베딩됨")
    
    # 6. 테스트 검색
    print("\n🔍 테스트 검색:")
    test_query = "sample9 iBGP BGP neighbor"
    results = collection.query(
        query_embeddings=embedder.embed([test_query]),
        n_results=5
    )
    
    metadatas = results.get('metadatas', [[]])[0]
    for i, meta in enumerate(metadatas):
        print(f"   {i+1}. {meta.get('filename', 'unknown')}")
        print(f"      장비: {meta.get('device_name', 'unknown')}")
        print(f"      섹션: {meta.get('section_type', 'unknown')}")

if __name__ == "__main__":
    create_chunk_embeddings() 