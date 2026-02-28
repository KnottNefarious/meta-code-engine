import os
import io
import ast
import json
import zipfile
import traceback
import urllib.request
import urllib.error

from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)


# ---------------- Home ----------------
@app.route('/')
def home():
    return render_template('index.html')


# ---------------- Single Snippet Analysis ----------------
@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        code = data.get('code', '')

        if not code.strip():
            return jsonify({'success': False, 'error': 'No code provided'}), 400

        engine = MetaCodeEngine()
        report = engine.orchestrate(code)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception:
        return jsonify({'success': False, 'error': traceback.format_exc()}), 500


# ---------------- GitHub Repository Analysis ----------------
@app.route('/api/analyze_repo', methods=['POST'])
def analyze_repo():
    try:
        data = request.json
        repo_url = data.get("url", "").strip()

        if not repo_url.startswith("https://github.com/"):
            return jsonify({'success': False, 'error': 'Invalid GitHub URL'}), 400

        # parse owner/repo
        parts = repo_url.replace("https://github.com/", "").replace(".git", "").split("/")
        if len(parts) < 2:
            return jsonify({'success': False, 'error': 'Invalid repository format'}), 400

        user, repo = parts[0], parts[1]

        # ---- Step 1: ask GitHub what the default branch is ----
        api_url = f"https://api.github.com/repos/{user}/{repo}"

        try:
            with urllib.request.urlopen(api_url, timeout=20) as response:
                meta_data = json.loads(response.read().decode())
                default_branch = meta_data.get("default_branch", "main")
        except Exception:
            return jsonify({'success': False, 'error': 'Could not read repository metadata from GitHub'}), 400

        # ---- Step 2: download repository zip ----
        zip_url = f"https://github.com/{user}/{repo}/archive/refs/heads/{default_branch}.zip"

        try:
            with urllib.request.urlopen(zip_url, timeout=40) as response:
                zip_bytes = io.BytesIO(response.read())
                z = zipfile.ZipFile(zip_bytes)
        except Exception:
            return jsonify({'success': False, 'error': 'Could not download repository'}), 400

        # ---- Step 3: collect all python files (cross-file analysis) ----
        collected_code = []

        for filename in z.namelist():
            if not filename.endswith(".py"):
                continue

            try:
                content = z.read(filename).decode("utf-8", errors="ignore")
            except Exception:
                continue

            collected_code.append(f"\n\n# ===== FILE: {filename} =====\n\n")
            collected_code.append(content)

        if not collected_code:
            return jsonify({'success': False, 'error': 'No Python files found in repository'}), 400

        final_program = "\n".join(collected_code)

        # ---- Step 4: run analyzer ----
        engine = MetaCodeEngine()
        report = engine.orchestrate(final_program)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception:
        return jsonify({'success': False, 'error': traceback.format_exc()}), 500


# ---------------- Health Check ----------------
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


# ---------------- Start Server ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
