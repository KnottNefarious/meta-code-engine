Meta-Code Engine

Meta-Code Engine is a web-based Python code analysis system that analyzes source code structure, detects potential issues, and produces a structured reasoning report about the program.

It is designed as a foundation for a future self-reasoning programming system — a program that can examine code and make logical conclusions about how it behaves.

---

Features

- Syntax validation
- Structural AST (Abstract Syntax Tree) analysis
- Complexity measurement
- Pattern detection
- Resolution suggestions
- Web interface for interactive analysis

---

How It Works

1. User pastes Python code into the website
2. Flask API receives the code
3. The MetaCodeEngine parses the code using Python's AST module
4. The engine produces a reasoning report
5. The report is returned to the browser as JSON and displayed

Architecture:

Browser → Flask API → MetaCodeEngine → AnalysisReport → JSON → UI

---

Running Locally

Install dependencies:

pip install -r requirements.txt

Run:

python app.py

Then open:

http://127.0.0.1:5000

---

API

POST /api/analyze

Body:
{
"code": "print('hello world')"
}

Returns:
Structured analysis report describing the code.

---

Goal

The long-term goal of this project is to develop a system capable of reasoning about programs — not just executing them — and eventually assisting in automated program understanding and correction.
