#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""modaas-docs Lambda MCP tool -- search over the shipped index.

Ported from static/kb/modaas-docs-mcp.py: same BM25 search, same tool schema,
packaged as a Lambda function with inlinePayload tool definition for AgentCore
Gateway integration.

Env:
  INDEX_PATH  path to index.json inside the Lambda deployment package
"""
import glob
import gzip
import json
import math
import os
import re

INDEX_PATH = os.environ.get("INDEX_PATH", "index.json")
K1 = 1.5
B = 0.75
MAX_LIMIT = 20
SNIPPET_CHARS = 600

_WORD = re.compile(r"[a-z0-9]+")
_CAMEL = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")

STOPWORDS = frozenset("""
a an and are as at be but by can do does for from get got has have how i if in
into is it its me my not of on or so that the their them then there these this
to use used using was what when where which who why will with you your
""".split())


def tokenize(text):
    out = []
    for raw in re.findall(r"[A-Za-z0-9_.\-]+", text):
        for part in _WORD.findall(raw.lower()):
            if len(part) > 1 and part not in STOPWORDS:
                out.append(part)
        for part in _CAMEL.findall(raw):
            p = part.lower()
            if len(p) > 1 and p not in STOPWORDS:
                out.append(p)
    return out


class Index:
    def __init__(self):
        self.chunks = []
        self.postings = {}
        self.lengths = []
        self.avg_len = 0.0
        self.by_id = {}
        self.sources = {}

    def load(self, path):
        if not os.path.exists(path):
            return self
        with open(path) as f:
            doc = json.load(f)
        docs = doc.get("chunks") or []
        docs.sort(key=lambda c: c.get("id", ""))
        self.chunks = docs
        for i, c in enumerate(docs):
            self.by_id[c["id"]] = c
            self.sources[c["source_path"].split("/", 1)[0]] = \
                self.sources.get(c["source_path"].split("/", 1)[0], 0) + 1
            terms = tokenize(c.get("text", "")) + tokenize(" ".join(c.get("heading_path") or [])) * 2
            self.lengths.append(len(terms) or 1)
            for t in terms:
                self.postings.setdefault(t, {})
                self.postings[t][i] = self.postings[t].get(i, 0) + 1
        if self.lengths:
            self.avg_len = sum(self.lengths) / float(len(self.lengths))
        return self

    def search(self, query, limit=5, source=None):
        if not self.chunks:
            return []
        q = tokenize(query)
        if not q:
            return []
        n = len(self.chunks)
        scores = {}
        for t in set(q):
            post = self.postings.get(t)
            if not post:
                continue
            idf = math.log(1.0 + (n - len(post) + 0.5) / (len(post) + 0.5))
            for i, tf in post.items():
                denom = tf + K1 * (1 - B + B * self.lengths[i] / self.avg_len)
                scores[i] = scores.get(i, 0.0) + idf * (tf * (K1 + 1)) / denom
        hits = []
        for i, s in scores.items():
            c = self.chunks[i]
            if source and not c["source_path"].startswith(source.rstrip("/") + "/"):
                continue
            hits.append((s, c))
        hits.sort(key=lambda kv: (-kv[0], kv[1]["id"]))
        return hits[:limit]


INDEX = Index()
INDEX.load(INDEX_PATH)


def handler(event, context):
    """Lambda handler for MCP tool calls from AgentCore Gateway."""
    params = event.get("parameters") or event.get("arguments") or event
    query = params.get("query", "")
    limit = min(int(params.get("limit", 5)), MAX_LIMIT)
    source = params.get("source")

    if not query.strip():
        return {"error": "query is required"}

    hits = INDEX.search(query, limit, source)
    results = [{
        "id": c["id"],
        "source_path": c["source_path"],
        "heading_path": c.get("heading_path") or [],
        "score": round(s, 4),
        "text": c["text"][:SNIPPET_CHARS],
    } for s, c in hits]

    return {"query": query, "results": results,
            "citation_rule": "Cite source_path for every claim."}
