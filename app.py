"""
app.py — Meta-Code Engine Flask application.

Endpoints:
  GET  /              Web UI
  GET  /health        Health check
  POST /analyze       SAST security analysis (paste code)
  POST /upload        Upload .py files for SAST analysis
  POST /github        Scan a GitHub repository
  POST /execute       Safe sandboxed code execution
  POST /monitor       Step-by-step execution trace
  POST /dissonance    Semantic code-quality analysis
  POST /compress      Pattern extraction + Kolmogorov complexity
  POST /compare       Structural comparison of two programs
  POST /resolve       Predict resolutions for dissonance issues
"""

import io
import os
import zipfile

import requests as req_lib
from flask import Flask, jsonify, render_template, request

from meta_code.compression   import KolmogorovComplexity, PatternExtractor
from meta_code.dissonance    import DissonanceDetector
from meta_code.execution     import ExecutionMonitor, HarmonicExecutor
from meta_code.meta_engine   import MetaCodeEngine
from meta_code.resolution    import ResolutionPredictor
from meta_code.transposition import StructuralAnalyzer, TranspositionFinder

app    = Flask(__name__)
engine = MetaCodeEngine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _require_json():
    data = request.get_json(silent=True)
    if not data:
        return None, (jsonify({"error": "No JSON body received"}), 400)
    return data, None


def _require_code(data, key="code"):
    code = data.get(key, "")
    if not code or not code.strip():
        return None, jsonify({"error": f"No code provided in '{key}' field."})
    return code, None


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return "ok", 200


# ---------------------------------------------------------------------------
# SAST — paste code
# ---------------------------------------------------------------------------

@app.post("/analyze")
def analyze_code():
    try:
        data, err = _require_json()
        if err:
            return err

        code = data.get("code", "")
        if not code.strip():
            return jsonify({"result": "No code provided."})

        report = engine.orchestrate(code)
        if not report.issues:
            return jsonify({"result": "✔ No vulnerabilities detected."})

        return jsonify({
            "result":      "\n\n".join(report.issues),
            "issue_count": len(report.issues),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# SAST — file upload
# ---------------------------------------------------------------------------

@app.post("/upload")
def upload_file():
    try:
        files    = request.files.getlist("file")
        findings = []

        for file in files:
            if not file or not file.filename:
                continue
            if not file.filename.lower().endswith(".py"):
                continue

            file.stream.seek(0)
            raw = file.stream.read()
            if not raw:
                continue
            if len(raw) > 200_000:
                return jsonify({"error": "File too large (max 200 KB per file)"}), 400

            code   = raw.decode("utf-8", errors="ignore")
            report = engine.orchestrate(code)
            for issue in report.issues:
                findings.append(f"──── {file.filename} ────\n{issue}")

        if not findings:
            return jsonify({"result": "✔ No vulnerabilities detected."})

        return jsonify({
            "result":      "\n\n".join(findings),
            "issue_count": len(findings),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# SAST — GitHub repo scan
# ---------------------------------------------------------------------------

@app.post("/github")
def analyze_github():
    try:
        data, err = _require_json()
        if err:
            return err

        repo_url = data.get("repo", "").strip()
        if not repo_url.startswith("https://github.com/"):
            return jsonify({"error": "Invalid GitHub URL — must start with https://github.com/"}), 400

        parts = repo_url.replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            return jsonify({"error": "Invalid repository format"}), 400

        owner, repo = parts[0], parts[1]
        headers     = {"User-Agent": "MetaCodeEngine-Scanner"}

        # Detect default branch
        info = req_lib.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=headers, timeout=20,
        )
        default_branch = info.json().get("default_branch", "main")

        # Download repo zip
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{default_branch}.zip"
        r = req_lib.get(zip_url, headers=headers, timeout=60)
        if r.status_code != 200:
            return jsonify({"error": "Failed to download repository"}), 400

        if len(r.content) > 8_000_000:
            return jsonify({"error": "Repository too large to analyze safely (max 8 MB)"}), 400

        z        = zipfile.ZipFile(io.BytesIO(r.content))
        findings = []

        for filename in z.namelist():
            if not filename.endswith(".py"):
                continue
            try:
                raw  = z.open(filename).read()
                code = raw.decode("utf-8", errors="ignore")
                if not code.strip():
                    continue
                report = engine.orchestrate(code)
                for issue in report.issues:
                    findings.append(f"──── {filename} ────\n{issue}")
            except Exception:
                continue

        if not findings:
            return jsonify({"result": "✔ No vulnerabilities detected."})

        return jsonify({
            "result":      "\n\n".join(findings),
            "issue_count": len(findings),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Safe Execution
# ---------------------------------------------------------------------------

@app.post("/execute")
def execute_code():
    try:
        data, err = _require_json()
        if err:
            return err

        code, err2 = _require_code(data)
        if err2:
            return err2

        executor = HarmonicExecutor()
        result   = executor.execute(code)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Execution Monitor
# ---------------------------------------------------------------------------

@app.post("/monitor")
def monitor_code():
    try:
        data, err = _require_json()
        if err:
            return err

        code, err2 = _require_code(data)
        if err2:
            return err2

        monitor = ExecutionMonitor()
        trace   = monitor.monitor(code)
        return jsonify(trace)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Dissonance Detection
# ---------------------------------------------------------------------------

@app.post("/dissonance")
def dissonance_check():
    try:
        data, err = _require_json()
        if err:
            return err

        code, err2 = _require_code(data)
        if err2:
            return err2

        detector = DissonanceDetector(code)
        detector.parse()
        detector.analyze()
        issues = detector.get_issues()

        if not issues:
            return jsonify({"result": "✔ No semantic issues detected.", "issues": []})

        return jsonify({
            "result": detector.report(),
            "issues": issues,
            "issue_count": len(issues),
            "consistent": detector.check_consistency(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Compression & Complexity
# ---------------------------------------------------------------------------

@app.post("/compress")
def compress_code():
    try:
        data, err = _require_json()
        if err:
            return err

        code, err2 = _require_code(data)
        if err2:
            return err2

        patterns   = PatternExtractor(code).extract_patterns()
        complexity = KolmogorovComplexity(code).compute_complexity()

        return jsonify({
            "patterns":   patterns,
            "complexity": complexity,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Structural Comparison (Transposition)
# ---------------------------------------------------------------------------

@app.post("/compare")
def compare_programs():
    try:
        data, err = _require_json()
        if err:
            return err

        code1 = data.get("code1", "").strip()
        code2 = data.get("code2", "").strip()
        if not code1 or not code2:
            return jsonify({"error": "Both 'code1' and 'code2' are required."}), 400

        transpositions = TranspositionFinder().find_transpositions(code1, code2)
        structure1     = StructuralAnalyzer().analyze_structure(code1)
        structure2     = StructuralAnalyzer().analyze_structure(code2)

        # Make structural_signature JSON-serializable (it's a tuple of tuples)
        structure1["structural_signature"] = list(structure1["structural_signature"])
        structure2["structural_signature"] = list(structure2["structural_signature"])

        return jsonify({
            "transpositions": transpositions,
            "structure_a":    structure1,
            "structure_b":    structure2,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Resolution Prediction
# ---------------------------------------------------------------------------

@app.post("/resolve")
def resolve_issues():
    try:
        data, err = _require_json()
        if err:
            return err

        issues = data.get("issues", [])
        if not isinstance(issues, list) or not issues:
            return jsonify({"error": "'issues' must be a non-empty list of strings."}), 400

        predictor = ResolutionPredictor(issues)
        predictor.analyze()
        predictions = predictor.predict_resolution()

        return jsonify({
            "predictions":  predictions,
            "issue_count":  len(issues),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
