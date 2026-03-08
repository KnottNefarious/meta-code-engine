#🐍 Meta-Code Engine 🐍

---

👉 Live App will be available if I get more stars ⭐⭐⭐⭐⭐  
[![Live Demo](https://img.shields.io/badge/Live-Demo-brightgreen)](https://a4c29939-30b5-4781-a821-3fa22ad8393d-00-1tg0ttwlolf5b.worf.replit.dev/)

"Launch Meta-Code-Engine" !Live App¡

🖥️ Screenshot 💉

![Screenshot](https://github.com/KnottNefarious/meta-code-engine/raw/main/pictures/Assets/Screenshot_20260301-195203~2.png)

Paste Python code, run analysis, and receive a structured reasoning and security report without executing the program.

---

static application security analyzer (SAST) for Python web applications.

Meta-Code Engine

Meta-Code Engine is an experimental program analysis tool that examines Python source code and produces a structured reasoning report describing how the code behaves.

Instead of only checking style or syntax like a linter, Meta-Code Engine attempts to interpret the logic and intent of a program.

---

## Quick Example

Paste Python code:

```python
def process(data):
    """
    Sum items in `data` that are greater than 10.

    Args:
        data: An iterable of numeric values.

    Returns:
        The sum (int or float) of items > 10. Returns 0 for empty input.
    """
    result = 0
    for item in data:
        if item > 10:
            result += item
    return result


# Example:
# >>> process([5, 12, 15])
# 27
```

Meta-Code Engine returns a reasoning summary:

### Detected Behavior

- Iteration over a collection
- Conditional filtering
- Accumulator pattern

### Logical Interpretation

«The function scans a dataset and sums only values greater than 10.»

### Complexity

- Time: O(n)
- Linear pass through input

### Risk Notes

- Fails if "data" is empty or non-iterable
- Assumes comparable values

You are not reading code anymore — you are reading an explanation.

---

## What It Is

Meta-Code Engine is a static analysis and reasoning system built on top of Python's Abstract Syntax Tree (AST). It parses source code and converts it into a semantic analysis report that a human can read.

The system sits between a linter and a debugger:

Tool | What it checks
--- | ---
Linter | Style problems
Debugger | Runtime state
Meta-Code Engine | Program behavior and structure

The engine does not execute your code (see "Sandbox / Safe execution" below for the limited executor used by some endpoints).

---

## Sandbox / Safe execution

Some endpoints provide limited, sandboxed execution and monitoring (for example: `/execute`, `/monitor`). The executor is restricted:

- Forbidden calls: `exec`, `eval`, `compile`, `__import__`, `open`, `breakpoint`, `input` and similar dangerous constructs.  
- Import statements (`import`, `from ... import ...`) are rejected in the sandbox.  
- The executor captures stdout and returns output, errors, and a snapshot of non-private variables.

If you prefer an analysis-only workflow, use the analysis endpoints and avoid the execution endpoints.

---

## Try It In 60 Seconds

```bash
git clone https://github.com/KnottNefarious/meta-code-engine.git
cd meta-code-engine
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000 and paste any Python file.

---

## Current Limitations

- Requires syntactically valid Python  
- Does not execute analyzed code unless you explicitly use the sandboxed execution endpoints  
- Does not perform symbolic execution (yet)

This project is experimental and evolving.

---

## License

MIT License
