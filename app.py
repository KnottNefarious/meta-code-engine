from flask import Flask, request, jsonify, render_template
import requests
import zipfile
import io
import os

from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)
engine = MetaCodeEngine()


# ---------------- Home Page ----------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------- Health checks ----------------
@app.route("/health")
def health():
    return jsonify({"status": "alive"})

@app.route("/ping")
def ping():
    return jsonify({"ping": "pong"})


# ---------------- Paste Code ----------------
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        code = request.json.get("code", "")
        report = engine.orchestrate(code)
        return jsonify({"issues": report.issues})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Upload File ----------------
@app.route("/upload", methods=["POST"])
def upload():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]
        code = file.read().decode("utf-8", errors="ignore")

        report = engine.orchestrate(code)
        return jsonify({"issues": report.issues})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Single GitHub File ----------------
@app.route("/github_file", methods=["POST"])
def github_file():
    try:
        url = request.json.get("url")

        if not url:
            return jsonify({"error": "Missing URL"}), 400

        r = requests.get(url, timeout=20)
        r.raise_for_status()

        code = r.text
        report = engine.orchestrate(code)

        return jsonify({"issues": report.issues})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Entire GitHub Repository ----------------
@app.route("/github_repo", methods=["POST"])
def github_repo():
    try:
        repo_url = request.json.get("url")
        if not repo_url:
            return jsonify({"error": "Missing repo URL"}), 400

        # convert repo URL to zip
        if repo_url.endswith("/"):
            repo_url = repo_url[:-1]

        zip_url = repo_url + "/archive/refs/heads/main.zip"

        r = requests.get(zip_url, timeout=60)
        r.raise_for_status()

        zip_bytes = io.BytesIO(r.content)
        z = zipfile.ZipFile(zip_bytes)

        all_issues = []

        for name in z.namelist():
            if name.endswith(".py"):
                with z.open(name) as f:
                    code = f.read().decode("utf-8", errors="ignore")
                    report = engine.orchestrate(code)

                    for issue in report.issues:
                        all_issues.append(f"[{name}]\\n{issue}")

        return jsonify({"issues": all_issues})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- Run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
