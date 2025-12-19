import json
import re
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone, ServerlessSpec
from llama_cpp import Llama

# ===============================
# CONFIGURATION
# ===============================

PINECONE_API_KEY = "pcsk_6vKsWK_TvbweB2duc1PEkpQ4ZhKhKt278yzDLggQPMQCvNohMcp5pLKuonWRjJGfyRGqgt"
INDEX_NAME = "vulnerability-index"
MODEL_PATH = "models/llama-2-7b-chat.Q4_K_M.gguf"
EMBEDDING_DIMENSION = 384  # all-MiniLM-L6-v2

# ===============================
# LOAD MODELS
# ===============================

print("[+] Loading embedding model...")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

print("[+] Loading LLaMA GGUF model...")
llm = Llama(
    model_path=MODEL_PATH,
    n_ctx=2048,
    temperature=0.1
)

# ===============================
# PINECONE SETUP
# ===============================

pc = Pinecone(api_key=PINECONE_API_KEY)
existing_indexes = pc.list_indexes().names()

if INDEX_NAME in existing_indexes:
    desc = pc.describe_index(INDEX_NAME)
    if desc.dimension != EMBEDDING_DIMENSION:
        raise ValueError(
            f"Index dimension {desc.dimension} does not match embedding dimension {EMBEDDING_DIMENSION}"
        )
else:
    print("[+] Creating Pinecone index...")
    pc.create_index(
        name=INDEX_NAME,
        dimension=EMBEDDING_DIMENSION,
        metric="cosine",
        spec=ServerlessSpec(cloud="aws", region="us-east-1")
    )

index = pc.Index(INDEX_NAME)

# ===============================
# INGEST VULNERABILITY DATA
# ===============================

def ingest_file(filepath: str):
    with open(filepath, "r") as f:
        lines = f.readlines()

    vectors = []
    for i, text in enumerate(lines):
        text = text.strip()
        if not text:
            continue
        vector = embedder.encode(text).tolist()
        vectors.append((f"{filepath}-{i}", vector, {"text": text}))

    if vectors:
        index.upsert(vectors)

print("[+] Ingesting vulnerability knowledge...")
ingest_file("data/owasp_top10.txt")
ingest_file("data/cve_samples.txt")

# ===============================
# USER INPUT HANDLING
# ===============================

def get_user_input():
    print("\nSelect input type:")
    print("1. Vulnerable code snippet")
    print("2. Security scan output (e.g., Nmap)")
    print("3. Dependency list")

    choice = input("Enter choice (1/2/3): ").strip()

    input_type_map = {
        "1": "code",
        "2": "scan",
        "3": "dependency"
    }

    if choice not in input_type_map:
        raise ValueError("Invalid input type selection")

    input_type = input_type_map[choice]

    print("\nPaste your input below. End with an empty line:\n")

    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)

    user_input = "\n".join(lines)

    if not user_input:
        raise ValueError("No input provided")

    return user_input, input_type

# ===============================
# RETRIEVAL
# ===============================

def retrieve_context(user_input: str, top_k: int = 3) -> str:
    query_vector = embedder.encode(user_input).tolist()
    results = index.query(
        vector=query_vector,
        top_k=top_k,
        include_metadata=True
    )
    return "\n".join(match["metadata"]["text"] for match in results["matches"])

# ===============================
# SAFE JSON PARSER (LLM HARDENING)
# ===============================

def safe_json_loads(text: str) -> dict:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON found in LLM output")

    json_text = match.group(0)
    json_text = re.sub(r",\s*([\]}])", r"\1", json_text)  # remove trailing commas

    return json.loads(json_text)

# ===============================
# ANALYSIS
# ===============================

def analyze_input(user_input: str, input_type: str) -> dict:
    context = retrieve_context(user_input)

    analysis_focus = {
        "code": (
            "Analyze ONLY application-level vulnerabilities such as "
            "SQL Injection, XSS, or Command Injection."
        ),
        "scan": (
            "Analyze ONLY network-level issues such as open ports, "
            "exposed services, and misconfigurations. "
            "DO NOT analyze or mention application-level vulnerabilities "
            "such as SQL Injection or XSS."
        ),
        "dependency": (
            "Analyze ONLY insecure, outdated, or vulnerable dependencies "
            "and known CVEs."
        )
    }

    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity expert. Respond ONLY with valid JSON."
        },
        {
            "role": "user",
            "content": f"""
Analyze the following security input.

Input Type: {input_type}
Analysis Focus: {analysis_focus[input_type]}

User Input:
{user_input}

Relevant Security Context:
{context}

Respond ONLY with a JSON object in this format:

{{
  "vulnerability": "string",
  "severity": "Low | Medium | High | Critical",
  "description": "string",
  "impact": "string",
  "remediation": ["string", "string"]
}}
"""
        }
    ]

    response = llm.create_chat_completion(
        messages=messages,
        max_tokens=300,
        temperature=0.1
    )

    raw_output = response["choices"][0]["message"]["content"]

    try:
        return safe_json_loads(raw_output)
    except Exception:
        print("\n[!] Raw LLM output (debug):\n")
        print(raw_output)
        return {
            "vulnerability": "Unknown",
            "severity": "Unknown",
            "description": "LLM output could not be parsed into JSON.",
            "impact": "Analysis incomplete due to malformed model output.",
            "remediation": []
        }

# ===============================
# MAIN
# ===============================

if __name__ == "__main__":
    print("[+] AI-Based Vulnerability Analysis System")

    user_input, input_type = get_user_input()

    print("\n[+] Running vulnerability analysis...")
    report = analyze_input(user_input, input_type)

    print("\n=== VULNERABILITY REPORT ===")
    print(json.dumps(report, indent=2))
