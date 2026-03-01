from flask import Flask, request, jsonify, render_template
from meta_code.meta_engine import MetaCodeEngine
import io
import zipfile
import requests

app = Flask(__name__)
engine = MetaCodeEngine()


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify({"status": "alive"})


# -------- analyze pasted code --------
@app.post("/analyze")
def analyze_code():
    data = request.get_json()
    code = data.get("code", "")

    report = engine.orchestrate(code)

    if not report.issues:
        return jsonify({"result": "No vulnerabilities found."})

    return jsonify({"result": "\n\n".join(report.issues)})


# -------- upload multiple files --------
@app.post("/upload")
def upload_file():
    files = request.files.getlist("file")

    findings = []

    for file in files:
        if not file.filename.endswith(".py"):
            continue

        code = file.read().decode(errors="ignore")
        report = engine.orchestrate(code)

        for issue in report.issues:
            findings.append(f"{file.filename}\n{issue}\n")

    if not findings:
        return jsonify({"result": "No vulnerabilities found."})

    return jsonify({"result": "\n".join(findings)})


# -------- github scan --------
@app.post("/github")
def analyze_github():
    data = request.get_json()
    repo_url = data.get("repo")

    parts = repo_url.replace("https://github.com/", "").split("/")
    owner, repo = parts[0], parts[1]

    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    info = requests.get(api_url, timeout=15)
    default_branch = info.json().get("default_branch", "main")

    zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{default_branch}.zip"
    r = requests.get(zip_url, timeout=40)

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

    return jsonify({"result": "\n".join(findings))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
