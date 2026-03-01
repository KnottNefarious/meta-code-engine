from flask import Flask, request, jsonify, render_template
from meta_code.meta_engine import MetaCodeEngine
import io
import zipfile
import requests

app = Flask(__name__)

# create analyzer
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
        if not data:
            return jsonify({"error": "No JSON body received"}), 400

        code = data.get("code", "")
        if not code.strip():
            return jsonify({"result": "No code provided."})

        report = engine.orchestrate(code)

        if not report.issues:
            return jsonify({"result": "No vulnerabilities found."})

        return jsonify({"result": "\n\n".join(report.issues)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- upload python files ----------------
@app.post("/upload")
def upload_file():
    try:
        files = request.files.getlist("file")
        findings = []

        for file in files:
            if not file or file.filename == "":
                continue

            if not file.filename.lower().endswith(".py"):
                continue

            # IMPORTANT: reset stream before reading
            file.stream.seek(0)
            raw = file.stream.read()

            if not raw:
                continue

            code = raw.decode("utf-8", errors="ignore")

            report = engine.orchestrate(code)

            for issue in report.issues:
                findings.append(f"{file.filename}\n{issue}\n")

        if not findings:
            return jsonify({"result": "No vulnerabilities found."})

        return jsonify({"result": "\n".join(findings)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- GitHub repo scanner ----------------
@app.post("/github")
def analyze_github():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"error": "No JSON body received"}), 400

        repo_url = data.get("repo", "").strip()
        if not repo_url.startswith("https://github.com/"):
            return jsonify({"error": "Invalid GitHub URL"}), 400

        # parse owner/repo
        parts = repo_url.replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            return jsonify({"error": "Invalid repository format"}), 400

        owner, repo = parts[0], parts[1]

        # detect default branch
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        info = requests.get(api_url, timeout=20)
        default_branch = info.json().get("default_branch", "main")

        # download zip
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{default_branch}.zip"
        r = requests.get(zip_url, timeout=60)

        if r.status_code != 200:
            return jsonify({"error": "Failed to download repository"}), 400

        z = zipfile.ZipFile(io.BytesIO(r.content))
        findings = []

        for filename in z.namelist():

            if not filename.endswith(".py"):
                continue

            try:
                raw = z.open(filename).read()
                if not raw:
                    continue

                code = raw.decode("utf-8", errors="ignore")

                report = engine.orchestrate(code)

                for issue in report.issues:
                    findings.append(f"{filename}\n{issue}\n")

            except Exception:
                continue

        if not findings:
            return jsonify({"result": "No vulnerabilities found."})

        return jsonify({"result": "\n".join(findings)})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- run ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)