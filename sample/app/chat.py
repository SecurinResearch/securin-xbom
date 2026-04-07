"""Chat endpoint — RAG pipeline with OpenAI + ChromaDB."""

import os

import chromadb
import tiktoken
from fastapi import APIRouter, Depends
from langchain.text_splitter import RecursiveCharacterTextSplitter
from openai import OpenAI

from app.auth import get_current_user
from app.models import ChatRequest, ChatResponse, DocumentUpload
from app.embeddings import get_embedding

router = APIRouter(tags=["chat"])

# Clients
openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
chroma_client = chromadb.HttpClient(host="localhost", port=8000)
collection = chroma_client.get_or_create_collection("documents")

# Tokenizer for counting
encoding = tiktoken.encoding_for_model("gpt-4o")

MODEL = "gpt-4o"


@router.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, user=Depends(get_current_user)):
    """Ask a question against the document store."""
    # Retrieve relevant chunks
    query_embedding = get_embedding(req.question)
    results = collection.query(query_embeddings=[query_embedding], n_results=5)

    context_chunks = results["documents"][0] if results["documents"] else []
    context = "\n\n".join(context_chunks)

    # Build prompt
    messages = [
        {"role": "system", "content": f"Answer based on this context:\n\n{context}"},
        {"role": "user", "content": req.question},
    ]

    # Call LLM
    response = openai_client.chat.completions.create(
        model=req.model,
        messages=messages,
        temperature=req.temperature,
        max_tokens=req.max_tokens,
    )

    answer = response.choices[0].message.content
    tokens = len(encoding.encode(answer))

    return ChatResponse(
        answer=answer,
        sources=[m.get("id", "") for m in (results.get("metadatas", [[]])[0])],
        model=req.model,
        tokens_used=tokens,
    )


@router.post("/documents")
def upload_document(doc: DocumentUpload, user=Depends(get_current_user)):
    """Upload and index a document for RAG retrieval."""
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    chunks = splitter.split_text(doc.content)

    embeddings = [get_embedding(chunk) for chunk in chunks]
    ids = [f"{doc.filename}_{i}" for i in range(len(chunks))]

    collection.add(documents=chunks, embeddings=embeddings, ids=ids)

    return {"indexed": len(chunks), "filename": doc.filename}
