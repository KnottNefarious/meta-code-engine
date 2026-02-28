import os
import ast
import io
import zipfile
import traceback
import urllib.request
import urllib.error

from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)


# ---------------- HOME ----------------
@app.route('/')
def home():
    return render_template('index.html')


# ---------------- SINGLE SNIPPET ANALYSIS ----------------
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


# ---------------- GITHUB REPOSITORY ANALYSIS ----------------
@app.route('/api/analyze_repo', methods=['POST'])
def analyze_repo():
    try:
        data = request.json
        repo_url = data.get("url", "").strip()

        if not repo_url.startswith("https://github.com/"):
            return jsonify({'success': False, 'error': 'Invalid GitHub URL'}), 400

        # Extract owner and repo
        parts = repo_url.replace("https://github.com/", "").strip("/").split("/")
        if len(parts) < 2:
            return jsonify({'success': False, 'error': 'Invalid repository format'}), 400

        user, repo = parts[0], parts[1].replace(".git", "")

        # ---------- DIRECT DOWNLOAD (NO API, NO REQUESTS LIB) ----------
        def try_download(branch):
            zip_url = f"https://github.com/{user}/{repo}/archive/refs/heads/{branch}.zip"
            try:
                with urllib.request.urlopen(zip_url, timeout=40) as response:
                    return response.read()
            except urllib.error.HTTPError:
                return None
            except urllib.error.URLError:
                return None

        zip_content = None

        # Try common branch names
        for branch in ["main", "master"]:
            zip_content = try_download(branch)
            if zip_content:
                break

        if not zip_content:
            return jsonify({
                'success': False,
                'error': 'Could not download repository (private repo or unsupported branch)'
            }), 400

        # ---------- UNZIP ----------
        zip_bytes = io.BytesIO(zip_content)
        z = zipfile.ZipFile(zip_bytes)

        definitions = []
        top_level = []

        for filename in z.namelist():
            if not filename.endswith(".py"):
                continue

            content = z.read(filename).decode("utf-8", errors="ignore")

            # Remove imports (prevents missing dependency parse errors)
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
            return jsonify({'success': False, 'error': 'No analyzable Python code found'}), 400

        # Combine into one analyzable program
        final_program = "import os\n\n"
        final_program += "\n\n".join(definitions)
        final_program += "\n\n"
        final_program += "\n".join(top_level)

        # ---------- ANALYZE ----------
        engine = MetaCodeEngine()
        report = engine.orchestrate(final_program)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception:
        return jsonify({'success': False, 'error': traceback.format_exc()}), 500


# ---------------- HEALTH ----------------
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


# ---------------- RUN SERVER ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
