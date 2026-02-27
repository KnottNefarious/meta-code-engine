import os
import ast
import io
import zipfile
import traceback
import urllib.request
import json

from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)


# ---------------- HOME ----------------
@app.route('/')
def home():
    return render_template('index.html')


# ---------------- SINGLE SNIPPET ----------------
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


# ---------------- GITHUB REPOSITORY SCANNER ----------------
@app.route('/api/analyze_repo', methods=['POST'])
def analyze_repo():
    try:
        data = request.json
        repo_url = data.get("url", "").strip()

        if not repo_url.startswith("https://github.com/"):
            return jsonify({'success': False, 'error': 'Invalid GitHub URL'}), 400

        parts = repo_url.replace("https://github.com/", "").split("/")
        if len(parts) < 2:
            return jsonify({'success': False, 'error': 'Invalid repository format'}), 400

        user, repo = parts[0], parts[1]
token = os.environ.get("GITHUB_TOKEN")

headers = {
    "User-Agent": "MetaCodeEngine-Scanner",
}

if token:
    headers["Authorization"] = f"token {token}"

        # ---- 1) Ask GitHub for default branch ----
        try:
            api_url = f"https://api.github.com/repos/{user}/{repo}"
            req = urllib.request.Request(api_url, headers=headers)

            with urllib.request.urlopen(req, timeout=20) as resp:
                repo_data = json.loads(resp.read().decode("utf-8"))

            default_branch = repo_data.get("default_branch", "main")

        except Exception:
            return jsonify({'success': False, 'error': 'GitHub rejected metadata request (repo missing, private, or rate-limited)'}), 400

        # ---- 2) Download repository ZIP ----
        try:
            zip_url = f"https://github.com/{user}/{repo}/archive/refs/heads/{default_branch}.zip"
            zip_req = urllib.request.Request(zip_url, headers=headers)

            with urllib.request.urlopen(zip_req, timeout=30) as resp:
                zip_bytes = io.BytesIO(resp.read())

        except Exception:
            return jsonify({'success': False, 'error': 'Failed to download repository archive'}), 400

        z = zipfile.ZipFile(zip_bytes)

        definitions = []
        top_level = []

        # -------- LARGE REPOSITORY FILTER --------
        SKIP_FOLDERS = [
            "venv/", ".venv/", "env/",
            "node_modules/",
            "tests/", "test/",
            "docs/", "examples/",
            "build/", "dist/",
            "__pycache__/",
            ".git/",
            "site-packages/"
        ]

        for filename in z.namelist():

            if not filename.endswith(".py"):
                continue

            # Skip dependency & non-app folders
            if any(folder in filename for folder in SKIP_FOLDERS):
                continue

            # Skip very large files (prevents crashes)
            try:
                if z.getinfo(filename).file_size > 200000:  # 200KB
                    continue
            except Exception:
                continue

            content = z.read(filename).decode("utf-8", errors="ignore")

            cleaned_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                cleaned_lines.append(line)

            cleaned_code = "\n".join(cleaned_lines)

            try:
                tree = ast.parse(cleaned_code)
            except Exception:
                continue

            for node in tree.body:
                segment = ast.get_source_segment(cleaned_code, node)
                if segment is None:
                    continue

                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    definitions.append(segment)
                else:
                    top_level.append(segment)

        if not definitions and not top_level:
            return jsonify({'success': False, 'error': 'No analyzable Python application code found'}), 400

        # Build virtual program
        final_program = "import os\n\n"
        final_program += "\n\n".join(definitions)
        final_program += "\n\n"
        final_program += "\n".join(top_level)

        engine = MetaCodeEngine()
        report = engine.orchestrate(final_program)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception:
        return jsonify({'success': False, 'error': traceback.format_exc()}), 500


@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


# ---------------- RUN ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
