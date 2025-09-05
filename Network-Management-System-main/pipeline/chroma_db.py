# pip install openai>=1.0.0 chromadb
import os, chromadb
from openai import OpenAI

OPENAI_EMBED_MODEL = "text-embedding-3-large"  # or "text-embedding-3-small"
EMBED_DIMS = None  # 예: 1024로 줄이고 싶으면 1024 지정 (모든 벡터에 동일 적용)

class OpenAIEmbedder:
    def __init__(self, model=OPENAI_EMBED_MODEL, dims: int | None = EMBED_DIMS):
        self.client = OpenAI()  # 환경변수 OPENAI_API_KEY 필요
        self.model = model
        self.dims = dims

    def embed(self, texts: list[str] | str) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]
        resp = self.client.embeddings.create(
            model=self.model,
            input=texts,
            **({"dimensions": self.dims} if self.dims else {})
        )
        return [d.embedding for d in resp.data]

class ChromaDB:
    def __init__(self, db_path: str, collection_name: str,
                 embedder: OpenAIEmbedder | None = None):
        self.db_path = db_path
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedder = embedder or OpenAIEmbedder()
        # 주의: 컬렉션에 넣는 임베딩 차원은 전부 동일해야 합니다.
        self.collection = self.client.get_or_create_collection(name=collection_name)

    def add_docs(self, ids: list[str], docs: list[str], metadatas: list[dict] | None = None):
        embeddings = self.embedder.embed(docs)
        self.collection.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)

    def query(self, text: str, n_results: int = 3):
        q_emb = self.embedder.embed(text)
        return self.collection.query(query_embeddings=q_emb, n_results=n_results)
