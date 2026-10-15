"""
InsiderLens - RAG (Retrieval-Augmented Generation) Pipeline
Indexes policy documents, playbooks, and detection knowledge into ChromaDB
for context-grounded copilot responses with source citations.
"""
import os
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Lazy imports to avoid crashing if not installed
_chromadb = None
_SentenceTransformer = None


def _ensure_imports():
    """Lazy-load heavy dependencies."""
    global _chromadb, _SentenceTransformer
    if _chromadb is None:
        import chromadb as _chromadb_mod
        _chromadb = _chromadb_mod
    if _SentenceTransformer is None:
        from sentence_transformers import SentenceTransformer as _ST
        _SentenceTransformer = _ST


# ── Chunking ────────────────────────────────────────────────────────────

def chunk_markdown(text: str, source_name: str, max_chunk_size: int = 500) -> List[Dict]:
    """
    Split a markdown document into semantically meaningful chunks.
    Each chunk preserves its section heading hierarchy for context.
    Returns list of {"text": ..., "source": ..., "section": ..., "chunk_id": ...}
    """
    lines = text.split("\n")
    chunks = []
    current_section = ""
    current_chunk_lines = []
    current_chunk_size = 0

    for line in lines:
        stripped = line.strip()

        # Track section headers
        if stripped.startswith("#"):
            # If we have accumulated content, save it as a chunk
            if current_chunk_lines:
                chunk_text = "\n".join(current_chunk_lines).strip()
                if len(chunk_text) > 30:  # Skip very short chunks
                    chunks.append({
                        "text": chunk_text,
                        "source": source_name,
                        "section": current_section,
                    })
                current_chunk_lines = []
                current_chunk_size = 0

            current_section = stripped.lstrip("#").strip()
            current_chunk_lines.append(line)
            current_chunk_size += len(line)
        else:
            current_chunk_lines.append(line)
            current_chunk_size += len(line)

            # Split if chunk gets too large
            if current_chunk_size > max_chunk_size and stripped == "":
                chunk_text = "\n".join(current_chunk_lines).strip()
                if len(chunk_text) > 30:
                    chunks.append({
                        "text": chunk_text,
                        "source": source_name,
                        "section": current_section,
                    })
                current_chunk_lines = []
                current_chunk_size = 0

    # Don't forget the last chunk
    if current_chunk_lines:
        chunk_text = "\n".join(current_chunk_lines).strip()
        if len(chunk_text) > 30:
            chunks.append({
                "text": chunk_text,
                "source": source_name,
                "section": current_section,
            })

    # Assign stable chunk IDs
    for i, chunk in enumerate(chunks):
        chunk_id = hashlib.md5(f"{source_name}:{i}:{chunk['text'][:50]}".encode()).hexdigest()[:12]
        chunk["chunk_id"] = chunk_id

    return chunks


def build_runtime_context_chunks(results_dir: Path) -> List[Dict]:
    """
    Build chunks from live pipeline results (risk summary, cases, alerts)
    so the copilot can answer questions about the current detection state.
    """
    chunks = []

    # Risk summary
    risk_path = results_dir / "risk_summary.csv"
    if risk_path.exists():
        import pandas as pd
        risk_df = pd.read_csv(risk_path)
        for _, row in risk_df.iterrows():
            text = (
                f"User {row['user_id']} has a risk score of {row['risk_score']:.1f} "
                f"with severity {row['severity'].upper()}. "
                f"This user has generated {row['alert_count']} alerts across "
                f"{row['case_count']} case(s)."
            )
            chunks.append({
                "text": text,
                "source": "risk_summary.csv",
                "section": f"Risk Profile: {row['user_id']}",
                "chunk_id": f"risk_{row['user_id']}",
            })

        # Overall summary chunk
        total_alerts = risk_df["alert_count"].sum()
        high_risk = risk_df[risk_df["severity"].isin(["high", "critical"])]
        overall = (
            f"Overall system status: {len(risk_df)} users monitored, "
            f"{int(total_alerts)} total alerts generated, "
            f"{len(high_risk)} high/critical risk users. "
            f"Highest risk user is {risk_df.iloc[0]['user_id']} "
            f"with score {risk_df.iloc[0]['risk_score']:.1f}."
        )
        chunks.append({
            "text": overall,
            "source": "risk_summary.csv",
            "section": "System Overview",
            "chunk_id": "risk_overview",
        })

    # Cases summary
    cases_path = results_dir / "cases_summary.csv"
    if cases_path.exists():
        import pandas as pd
        cases_df = pd.read_csv(cases_path)
        for _, row in cases_df.iterrows():
            text = (
                f"Case {row['case_id']} involves user {row['user_id']}. "
                f"Risk score: {row['risk_score']:.1f}, severity: {row['severity'].upper()}. "
                f"Number of alerts: {row['alert_count']}. "
                f"First seen: {row.get('first_seen', 'N/A')}, "
                f"Last seen: {row.get('last_seen', 'N/A')}. "
                f"Status: {row.get('status', 'open')}."
            )
            chunks.append({
                "text": text,
                "source": "cases_summary.csv",
                "section": f"Case: {row['case_id']}",
                "chunk_id": f"case_{row['case_id']}",
            })

    # Explanations
    exp_path = results_dir / "explanations.json"
    if exp_path.exists():
        with open(exp_path, encoding="utf-8") as f:
            explanations = json.load(f)
        for case_id, exp in explanations.items():
            summary = exp.get("summary", "")
            why = exp.get("why_flagged", [])
            actions = exp.get("recommended_actions", [])
            text = (
                f"Explanation for {case_id}: {summary} "
                f"Flagged because: {'; '.join(why) if why else 'N/A'}. "
                f"Recommended actions: {'; '.join(actions) if actions else 'N/A'}."
            )
            chunks.append({
                "text": text,
                "source": "explanations.json",
                "section": f"Explanation: {case_id}",
                "chunk_id": f"exp_{case_id}",
            })

    # Alerts summary by detector
    alerts_path = results_dir / "alerts.csv"
    if alerts_path.exists():
        import pandas as pd
        alerts_df = pd.read_csv(alerts_path)
        for detector, group in alerts_df.groupby("detector"):
            users = group["user_id"].unique()
            avg_score = group["score"].mean()
            text = (
                f"The {detector} detector generated {len(group)} alerts "
                f"affecting {len(users)} user(s): {', '.join(users[:5])}. "
                f"Average alert score: {avg_score:.2f}. "
                f"Score range: {group['score'].min():.2f} to {group['score'].max():.2f}."
            )
            chunks.append({
                "text": text,
                "source": "alerts.csv",
                "section": f"Detector Summary: {detector}",
                "chunk_id": f"detector_{detector}",
            })

        # Per-user alert breakdown
        for user_id, user_group in alerts_df.groupby("user_id"):
            detectors_hit = user_group["detector"].unique()
            text = (
                f"User {user_id} has {len(user_group)} alerts from "
                f"detectors: {', '.join(detectors_hit)}. "
                f"Highest alert score: {user_group['score'].max():.2f}. "
                f"Average score: {user_group['score'].mean():.2f}."
            )
            chunks.append({
                "text": text,
                "source": "alerts.csv",
                "section": f"User Alert Profile: {user_id}",
                "chunk_id": f"alerts_{user_id}",
            })

    return chunks


# ── RAG Engine ──────────────────────────────────────────────────────────

class RAGPipeline:
    """
    Retrieval-Augmented Generation pipeline using ChromaDB + sentence-transformers.
    Indexes policy documents, playbooks, detection methodology, and live results.
    Retrieves relevant context for copilot queries with source citations.
    """

    COLLECTION_NAME = "insiderlens_knowledge"

    def __init__(
        self,
        policies_dir: Optional[Path] = None,
        results_dir: Optional[Path] = None,
        embedding_model_name: str = "all-MiniLM-L6-v2",
        persist_dir: Optional[str] = None,
    ):
        _ensure_imports()

        self.policies_dir = policies_dir or Path(__file__).parent.parent / "policies"
        self.results_dir = results_dir or Path(__file__).parent.parent / "results"
        self.embedding_model_name = embedding_model_name

        # Initialize embedding model
        self._embedding_model = None

        # Initialize ChromaDB (in-memory for hackathon speed)
        if persist_dir:
            self.client = _chromadb.PersistentClient(path=persist_dir)
        else:
            self.client = _chromadb.Client()

        self.collection = None
        self._indexed = False

    def _get_embedding_model(self):
        if self._embedding_model is None:
            self._embedding_model = _SentenceTransformer(self.embedding_model_name)
        return self._embedding_model

    def _embed(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for a list of texts."""
        model = self._get_embedding_model()
        embeddings = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)
        return embeddings.tolist()

    def index_documents(self, force_reindex: bool = False):
        """
        Index all knowledge sources: policies, playbooks, methodology docs,
        and live pipeline results.
        """
        # Check if already indexed
        try:
            self.collection = self.client.get_collection(self.COLLECTION_NAME)
            if self.collection.count() > 0 and not force_reindex:
                self._indexed = True
                return
            # Delete existing to reindex
            self.client.delete_collection(self.COLLECTION_NAME)
        except Exception:
            pass

        self.collection = self.client.create_collection(
            name=self.COLLECTION_NAME,
            metadata={"description": "InsiderLens knowledge base for RAG copilot"},
        )

        all_chunks = []

        # 1. Index policy and methodology documents
        if self.policies_dir.exists():
            for md_file in self.policies_dir.glob("*.md"):
                try:
                    text = md_file.read_text(encoding="utf-8", errors="replace")
                    chunks = chunk_markdown(text, source_name=md_file.name)
                    all_chunks.extend(chunks)
                    print(f"  [RAG] Indexed {md_file.name}: {len(chunks)} chunks")
                except Exception as e:
                    print(f"  [RAG] Failed to index {md_file.name}: {e}")

        # 2. Index live pipeline results
        if self.results_dir.exists():
            try:
                runtime_chunks = build_runtime_context_chunks(self.results_dir)
                all_chunks.extend(runtime_chunks)
                print(f"  [RAG] Indexed pipeline results: {len(runtime_chunks)} chunks")
            except Exception as e:
                print(f"  [RAG] Failed to index results: {e}")

        if not all_chunks:
            print("  [RAG] Warning: No documents to index!")
            self._indexed = False
            return

        # 3. Embed and store in ChromaDB
        texts = [c["text"] for c in all_chunks]
        ids = [c["chunk_id"] for c in all_chunks]
        metadatas = [{"source": c["source"], "section": c["section"]} for c in all_chunks]

        # Embed in batches to avoid memory issues
        batch_size = 64
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i + batch_size]
            batch_ids = ids[i:i + batch_size]
            batch_meta = metadatas[i:i + batch_size]
            batch_embeddings = self._embed(batch_texts)

            self.collection.add(
                documents=batch_texts,
                embeddings=batch_embeddings,
                ids=batch_ids,
                metadatas=batch_meta,
            )

        self._indexed = True
        print(f"  [RAG] Total indexed: {len(all_chunks)} chunks from "
              f"{len(set(c['source'] for c in all_chunks))} sources")

    def retrieve(self, query: str, n_results: int = 5, score_threshold: float = 0.35) -> List[Dict]:
        """
        Retrieve the most relevant chunks for a query.
        Returns list of {"text", "source", "section", "score"}.
        Only returns results above the relevance threshold.
        """
        if not self._indexed or self.collection is None:
            return []

        query_embedding = self._embed([query])

        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=min(n_results, self.collection.count()),
            include=["documents", "metadatas", "distances"],
        )

        retrieved = []
        for i, doc in enumerate(results["documents"][0]):
            # ChromaDB returns L2 distances; convert to similarity score
            distance = results["distances"][0][i]
            # For normalized embeddings, distance ∈ [0, 2]; similarity = 1 - distance/2
            similarity = 1.0 - (distance / 2.0)

            if similarity >= score_threshold:
                retrieved.append({
                    "text": doc,
                    "source": results["metadatas"][0][i]["source"],
                    "section": results["metadatas"][0][i]["section"],
                    "score": round(similarity, 3),
                })

        return retrieved

    def build_context_with_citations(self, query: str, n_results: int = 5) -> Tuple[str, List[Dict]]:
        """
        Build a context string with source citations for the LLM prompt.
        Returns (context_string, list_of_sources).
        """
        retrieved = self.retrieve(query, n_results=n_results)

        if not retrieved:
            return "", []

        context_parts = []
        sources = []
        seen_sources = set()

        for i, item in enumerate(retrieved, 1):
            context_parts.append(
                f"[Source {i}: {item['source']} > {item['section']}]\n{item['text']}"
            )
            source_key = f"{item['source']}:{item['section']}"
            if source_key not in seen_sources:
                sources.append({
                    "source": item["source"],
                    "section": item["section"],
                    "relevance": item["score"],
                })
                seen_sources.add(source_key)

        context_string = "\n\n---\n\n".join(context_parts)
        return context_string, sources

    def is_ready(self) -> bool:
        """Check if the RAG pipeline is indexed and ready."""
        return self._indexed and self.collection is not None and self.collection.count() > 0
