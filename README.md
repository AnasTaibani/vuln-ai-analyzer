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
Setup Instructions

1. Clone the Repository
```bash
git clone https://github.com/<your-username>/vuln-ai-analyzer.git
cd vuln-ai-analyzer
```

3. Create a Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install Dependencies
```bash
pip install -r requirements.txt
```

4. Configure Pinecone
Set your Pinecone API key as an environment variable:
```bash
export PINECONE_API_KEY="your_api_key_here"
```

5. Add LLaMA GGUF Model
```bash
Download a GGUF LLaMA model (for example llama-2-7b-chat.Q4_K_M.gguf) and place it inside the models/ directory:

models/
└── llama-2-7b-chat.Q4_K_M.gguf
```

The model file is not included in the repository due to size and licensing constraints.

## How to Run

Run the application using:

```bash
python main.py
```


You will be prompted to select an input type:

1. Vulnerable code snippet
2. Security scan output (e.g., Nmap)
3. Dependency list
Paste the input and end with an empty line to begin analysis.

## Example
Input (Code Snippet)
```bash
1
query = "SELECT * FROM users WHERE id=" + user
```
Output
```bash
=== VULNERABILITY REPORT ===
{
  "vulnerability": "SQL Injection",
  "severity": "Low",
  "description": "The user input 'user' is concatenated into an SQL query without proper sanitization, potentially allowing an attacker to inject malicious SQL code and gain unauthorized access to sensitive data.",
  "impact": "Data breach",
  "remediation": [
    "Use parameterized queries or prepared statements to prevent untrusted input from being concatenated into SQL queries."
  ]
}




