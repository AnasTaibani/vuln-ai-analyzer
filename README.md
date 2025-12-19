# AI-Based Vulnerability Analysis System

## Overview

This project is a command-line **AI-based vulnerability analysis system** that analyzes security-related inputs and generates a **structured vulnerability report**.

It uses:
- An **embedding model** for semantic representation of inputs
- **Pinecone** as a vector database to retrieve relevant vulnerability context
- A **local LLaMA GGUF model** (via `llama-cpp-python`) to reason over the retrieved context and generate results

The system follows a **Retrieval-Augmented Generation (RAG)** pipeline and performs all large language model inference **locally**.

---

## Supported Input Types

The system accepts one input at a time:

1. Vulnerable code snippets  
2. Security scan output (e.g., Nmap)  
3. Dependency lists (e.g., `requirements.txt`)

---

## Architecture

User Input
↓
Embedding Model
↓
Pinecone Vector Database
↓
Relevant Vulnerability Context
↓
Local LLaMA GGUF Model
↓
Structured Vulnerability Report (JSON)

yaml
Copy code

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/vuln-ai-analyzer.git
cd vuln-ai-analyzer
2. Create Virtual Environment
bash
Copy code
python3 -m venv venv
source venv/bin/activate
3. Install Dependencies
bash
Copy code
pip install -r requirements.txt
4. Configure Pinecone
Set your Pinecone API key:

bash
Copy code
export PINECONE_API_KEY="your_api_key_here"
5. Add LLaMA Model
Download a GGUF LLaMA model (e.g. llama-2-7b-chat.Q4_K_M.gguf) and place it in:

Copy code
models/
The model file is not included in the repository.

How to Run
bash
Copy code
python main.py
You will be prompted to select an input type:

markdown
Copy code
1. Vulnerable code snippet
2. Security scan output
3. Dependency list
Paste the input and end with an empty line to begin analysis.

Example
Input (Code Snippet)
text
Copy code
query = "SELECT * FROM users WHERE id=" + user
Output
json
Copy code
{
  "vulnerability": "SQL Injection",
  "severity": "Low",
  "description": "User input is concatenated directly into an SQL query without sanitization.",
  "impact": "Unauthorized database access",
  "remediation": [
    "Use parameterized queries or prepared statements"
  ]
}
Notes
LLM inference is performed entirely locally

Pinecone is used only for vector similarity retrieval

Output is intentionally structured for easy parsing and extension

