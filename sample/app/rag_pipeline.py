"""RAG Pipeline — document ingestion and retrieval with LangChain."""

import os

import chromadb
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain.chains import RetrievalQA
from langchain_community.vectorstores import Chroma


# --- Embeddings ---

embeddings = OpenAIEmbeddings(
    model="text-embedding-3-small",
    openai_api_key=os.environ.get("OPENAI_API_KEY"),
)


# --- Vector Store ---

chroma_client = chromadb.HttpClient(host="localhost", port=8000)

vectorstore = Chroma(
    client=chroma_client,
    collection_name="rag_documents",
    embedding_function=embeddings,
)


# --- LLM ---

llm = ChatOpenAI(
    model="gpt-4o",
    temperature=0.3,
    openai_api_key=os.environ.get("OPENAI_API_KEY"),
)

fallback_llm = ChatOpenAI(
    model="gpt-4o-mini",
    temperature=0.5,
)


# --- RAG Chain ---

qa_chain = RetrievalQA.from_chain_type(
    llm=llm,
    chain_type="stuff",
    retriever=vectorstore.as_retriever(search_kwargs={"k": 5}),
)


def ingest_document(text: str, metadata: dict | None = None) -> int:
    """Split and ingest a document into the vector store."""
    splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
    chunks = splitter.split_text(text)

    vectorstore.add_texts(texts=chunks, metadatas=[metadata or {}] * len(chunks))
    return len(chunks)


def query(question: str) -> str:
    """Run a RAG query against the document store."""
    return qa_chain.run(question)
