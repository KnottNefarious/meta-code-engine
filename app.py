from flask import Flask, request, jsonify, render_template
from meta_code.meta_engine import MetaCodeEngine
import io
import zipfile
import requests

app = Flask(__name__)

engine = MetaCodeEngine()

# ---------------- UI ----------------
@app.get("/")
def index():
    return render_template("index.html")


# ---------------- health check ----------------
@app.get("/health")
def health():
    return jsonify({"status": "alive"})


# ---------------- analyze pasted code ----------------
@app.post("/analyze")
def analyze_code():
    try:
        data = request.get_json(silent=True)

        if not data or "code" not in data:
            return jsonify({"error": "No code provided"}), 400

        code = data["code"]

        report = engine.orchestrate(code)

        if not report.issues:
            return jsonify({"result": "No vulnerabilities found."})

        return jsonify({"result": "\n\n".join(report.issues)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- upload python file ----------------
@app.post("/upload")
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]

        if not file.filename.endswith(".py"):
            return jsonify({"error": "Only .py files allowed"}), 400

        code = file.read().decode(errors="ignore")

        report = engine.orchestrate(code)

        if not report.issues:
            return jsonify({"result": "No vulnerabilities found."})

        return jsonify({"result": "\n\n".join(report.issues)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- GitHub repo scanner ----------------
@app.post("/analyze_repo")   # <-- IMPORTANT FIX
def analyze_github():
    try:
        data = request.get_json(silent=True)

        if not data or "repo" not in data:
            return jsonify({"error": "No repository URL provided"}), 400

        repo_url = data["repo"]

        if not repo_url.startswith("https://github.com/"):
            return jsonify({"error": "Only GitHub repositories allowed"}), 400

        if repo_url.endswith("/"):
            repo_url = repo_url[:-1]

        zip_url = repo_url + "/archive/refs/heads/main.zip"

        r = requests.get(zip_url, timeout=30)

        if r.status_code != 200:
            return jsonify({"error": "Could not download repo (wrong branch or private repo)"}), 400

        z = zipfile.ZipFile(io.BytesIO(r.content))

        findings = []

        for filename in z.namelist():
            if filename.endswith(".py"):
                code = z.read(filename).decode(errors="ignore")
                report = engine.orchestrate(code)

                for issue in report.issues:
                    findings.append(f"{filename}\n{issue}\n")

        if not findings:
            return jsonify({"result": "No vulnerabilities found."})

        return jsonify({"result": "\n".join(findings)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
