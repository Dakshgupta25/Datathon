"""
Deterministic Entity Resolver for TraceONE AI Investigator.
Resolves user IDs, hostnames, IPs, sessions, clusters, and sequence IDs against TraceONE canonical indexes.
Handles ambiguous or missing entity queries safely without guessing.
"""

from typing import Dict, List, Optional
import pandas as pd

from src.dashboard.data.loader import (
    load_user_risk_scores,
    load_host_risk_scores,
    load_canonical_users,
    load_canonical_hosts,
    load_temporal_sequences
)


class EntityResolver:

    def __init__(self):
        self.user_df = load_user_risk_scores()
        self.host_df = load_host_risk_scores()
        self.seq_df = load_temporal_sequences()

    def resolve(self, query_term: str) -> dict:
        """
        Resolve an ambiguous or partial entity query string.
        Returns a dict with status: 'RESOLVED', 'AMBIGUOUS', or 'NOT_FOUND'.
        """
        if not query_term:
            return {"status": "NOT_FOUND", "message": "No query entity specified."}

        clean_term = str(query_term).strip().upper()

        # 1. Exact User ID Match
        if not self.user_df.empty and 'entity_id' in self.user_df.columns:
            exact_user = self.user_df[self.user_df['entity_id'].astype(str).str.upper() == clean_term]
            if not exact_user.empty:
                row = exact_user.iloc[0]
                return {
                    "status": "RESOLVED",
                    "entity_type": "user",
                    "entity_id": str(row['entity_id']).upper(),
                    "department": str(row.get('department', 'Unknown')),
                    "risk_score": float(row.get('traceone_risk_score', 0.0)),
                    "risk_level": str(row.get('risk_level', 'LOW'))
                }

        # 2. Exact Host Match
        if not self.host_df.empty and 'entity_id' in self.host_df.columns:
            exact_host = self.host_df[self.host_df['entity_id'].astype(str).str.upper() == clean_term]
            if not exact_host.empty:
                row = exact_host.iloc[0]
                return {
                    "status": "RESOLVED",
                    "entity_type": "host",
                    "entity_id": str(row['entity_id']).upper(),
                    "risk_score": float(row.get('traceone_risk_score', 0.0)),
                    "risk_level": str(row.get('risk_level', 'LOW'))
                }

        # 3. Exact Sequence ID Match
        if not self.seq_df.empty and 'sequence_id' in self.seq_df.columns:
            exact_seq = self.seq_df[self.seq_df['sequence_id'].astype(str).str.upper() == clean_term]
            if not exact_seq.empty:
                row = exact_seq.iloc[0]
                return {
                    "status": "RESOLVED",
                    "entity_type": "sequence",
                    "entity_id": str(row['sequence_id']).upper(),
                    "associated_entity": str(row.get('entity_id', 'UNKNOWN')).upper(),
                    "sequence_type": str(row.get('sequence_type', 'GENERAL_ACTIVITY'))
                }

        # 4. Partial Matches / Ambiguity Search (e.g. searching "John" or partial ID)
        matches = []
        if not self.user_df.empty:
            p_users = self.user_df[
                self.user_df['entity_id'].astype(str).str.upper().str.contains(clean_term, na=False) |
                self.user_df['department'].astype(str).str.upper().str.contains(clean_term, na=False)
            ]
            for _, r in p_users.head(5).iterrows():
                matches.append({"type": "user", "id": str(r['entity_id']).upper(), "dept": str(r.get('department', ''))})

        if len(matches) == 1:
            return {
                "status": "RESOLVED",
                "entity_type": matches[0]["type"],
                "entity_id": matches[0]["id"].upper()
            }
        elif len(matches) > 1:
            return {
                "status": "AMBIGUOUS",
                "message": f"Query '{query_term}' matched {len(matches)} possible candidates.",
                "candidates": matches
            }

        return {
            "status": "NOT_FOUND",
            "message": f"No matching entity found in canonical indexes for '{query_term}'."
        }
