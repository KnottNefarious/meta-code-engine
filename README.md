
Meta-Code Engine     Live App

""Launch Meta-Code-Engine"    !Live App¡

[![Launch Meta-Code-Engine](https://img.shields.io/badge/Launch-Meta--Code--Engine-3b82f6?style=for-the-badge&logo=python&logoColor=white)](https://20af8bd1-6406-4c04-8c1a-b8012ca55334-00-17nko5zx65rb3.riker.replit.dev/)

Meta-Code Engine is a static application security analyzer (SAST) for Python web applications.

It analyzes Python source code without running it and determines whether attacker-controlled input can reach dangerous operations such as OS commands, databases, file access, network requests, or browser output.

Instead of simple pattern matching, the engine performs taint flow + control-flow analysis and reconstructs real attack paths through the program.

---[![Launch Meta-Code-Engine](assets/ezgif.com-animated-gif-maker.gif)](https://20af8bd1-6406-4c04-8c1a-b8012ca55334-00-17nko5zx65rb3.riker.replit.dev/)

What It Does 🐍...

The analyzer models a real attacker interacting with a Flask-style web app:

HTTP Request → Program Logic → Sensitive Operation

It tracks untrusted data from web request sources and determines whether it can influence a security-critical action.

The engine also understands defensive code (authorization checks), allowing it to avoid many false positives.

What most beginner analyzers do:
pattern matching

what mine does:
data flow tracking (taint analysis)
+ semantic authorization reasoning
(IDOR + Missing Authorization) is the unusual part — many simple open-source scanners don’t even attempt that.
---
 
Detected Vulnerabilities 👌

Currently the engine detects:

Remote Code & System

- Command Injection (subprocess / shell=True)
- Unsafe Deserialization (pickle / yaml loads)

Database

- SQL Injection

Filesystem

- Path Traversal / Arbitrary File Read

Web Application Logic

- Insecure Direct Object Reference (IDOR)
- Missing authorization checks

Network

- Server-Side Request Forgery (SSRF)

Web Browser

- Cross-Site Scripting (XSS)
- Open Redirect

Each finding includes:

- Severity
- Exploitability likelihood
- Attack path reconstruction
- Explanation
- Suggested fix

---
Three working layers:

   1.Source detection
   •Flask request taint source

   2.Propagation engine
   •Variable assignment tracking
   •Branch awareness

   3.Sink reasoning
   •HTML response detection
   •SQL query detection
   •File system detection

Together form the classic model:
   •Source → Flow → Sink
     
That model is exactly how professional SAST tools are designed.

Capability:

Taint sources.       ✔
Propagation.         ✔
Sanitizers.          ✔
Overwrite detection  ✔
Re-taint detection   ✔
Sink analysis        ✔
---

Example Output 📝

Command Injection
Severity: CRITICAL
Exploitability: VERY LIKELY
Attack Path: request → get → cmd
Sink: subprocess(shell=True)
Why: User input executed by OS shell
Fix: Avoid shell=True and pass arguments as a list

---

Key Features 📊

- Static analysis (no code execution required)
- Path-sensitive taint tracking
- Control-flow aware (understands if-statements and authorization)
- Attack path reconstruction
- Exploitability scoring
- Web interface (Flask)
- Mobile friendly UI

---

Supported Input Sources (Flask)

The analyzer treats the following as attacker-controlled:

- "request.args"
- "request.form"
- "request.json"
- "request.headers"
- "request.cookies"
- "request.data"

---

How It Works (Technical) 🧠

1. Python code is parsed into an Abstract Syntax Tree (AST)
2. A symbolic execution engine walks the program
3. Tainted values are tracked across variables and function calls
4. When tainted data reaches a security sink, a vulnerability is reported
5. Authorization checks are detected and suppress false positives

This makes the tool closer to a security code reviewer than a linter.

---

Running Locally

Clone the repository: 🤯

git clone https://github.com/KnottNefarious/meta-code-engine.git
cd meta-code-engine

Install dependencies:

pip install -r requirements.txt

Run the server:

python app.py

Open:

http://localhost:5000

---

Project Structure

app.py                → Flask interface
meta_code/meta_engine.py → security analysis engine
templates/index.html  → web UI
tests/                → example test cases

---

Why This Tool Exists

Most linters check syntax.

Meta-Code Engine checks security behavior.

It answers the question:

«“If an attacker sends a request to this program, 
what can they make it do?”» 🤷‍♂️

---

License

MIT
