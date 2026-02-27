import os
import ast
import traceback
from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('index.html')


# ---------------- SINGLE CODE ----------------
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


# ---------------- PROJECT ANALYSIS ----------------
@app.route('/api/analyze_project', methods=['POST'])
def analyze_project():
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No files uploaded'}), 400

        uploaded_files = request.files.getlist('files')

        definitions = []
        top_level = []

        for file in uploaded_files:
            if not file.filename.endswith(".py"):
                continue

            content = file.read().decode('utf-8', errors='ignore')

            # remove imports
            cleaned_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                cleaned_lines.append(line)

            cleaned_code = "\n".join(cleaned_lines)

            # parse AST
            try:
                tree = ast.parse(cleaned_code)
            except Exception:
                continue

            # separate definitions from execution
            for node in tree.body:
                segment = ast.get_source_segment(cleaned_code, node)
                if segment is None:
                    continue

                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    definitions.append(segment)
                else:
                    top_level.append(segment)

        # force base import
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
