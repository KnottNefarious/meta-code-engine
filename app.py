import os
import traceback
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
        error_text = traceback.format_exc()
        print(error_text)
        return jsonify({'success': False, 'error': error_text}), 500


# ---------------- PROJECT ANALYSIS (MULTI-FILE) ----------------
@app.route('/api/analyze_project', methods=['POST'])
def analyze_project():
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No files uploaded'}), 400

        uploaded_files = request.files.getlist('files')

        combined_parts = []

        # IMPORTANT: provide base imports so merged code still works
        combined_parts.append("import os\n")

        for file in uploaded_files:
            filename = file.filename

            if not filename.endswith('.py'):
                continue

            content = file.read().decode('utf-8', errors='ignore')

            cleaned_lines = []
            for line in content.splitlines():
                stripped = line.strip()

                # remove project imports (we embed everything together)
                if stripped.startswith("import "):
                    continue
                if stripped.startswith("from "):
                    continue

                cleaned_lines.append(line)

            cleaned_code = "\n".join(cleaned_lines)

            combined_parts.append(f"\n# ===== FILE: {filename} =====\n")
            combined_parts.append(cleaned_code)

        full_program = "\n".join(combined_parts)

        if not full_program.strip():
            return jsonify({'success': False, 'error': 'No Python code found'}), 400

        engine = MetaCodeEngine()
        report = engine.orchestrate(full_program)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception:
        error_text = traceback.format_exc()
        print(error_text)
        return jsonify({'success': False, 'error': error_text}), 500


# ---------------- HEALTH CHECK ----------------
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


# ---------------- RUN SERVER ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
