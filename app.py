import os
import ast
import io
import zipfile
import traceback
import urllib.request

from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)


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


# ---------------- GITHUB REPO ANALYSIS ----------------
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

        zip_url = f"https://github.com/{user}/{repo}/archive/refs/heads/main.zip"

        # DOWNLOAD USING BUILT-IN PYTHON (NO REQUESTS LIBRARY)
        try:
            response = urllib.request.urlopen(zip_url, timeout=30)
            zip_bytes = io.BytesIO(response.read())
        except Exception:
            return jsonify({'success': False, 'error': 'Could not download repository (check repo exists and is public)'}), 400

        z = zipfile.ZipFile(zip_bytes)

        definitions = []
        top_level = []

        for filename in z.namelist():
            if not filename.endswith(".py"):
                continue

            content = z.read(filename).decode("utf-8", errors="ignore")

            # remove imports
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
            return jsonify({'success': False, 'error': 'No Python files found in repository'}), 400

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


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
