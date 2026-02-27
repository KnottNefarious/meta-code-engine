import os
from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)

# ---------------- Home ----------------
@app.route('/')
def home():
    return render_template('index.html')


# ---------------- Single snippet analysis ----------------
@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        code = data.get('code', '')

        if not code.strip():
            return jsonify({'success': False, 'error': 'No code'}), 400

        engine = MetaCodeEngine()
        report = engine.orchestrate(code)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------- MULTI-FILE PROJECT ANALYSIS ----------------
@app.route('/api/analyze_project', methods=['POST'])
def analyze_project():
    try:
        if 'files' not in request.files:
            return jsonify({'success': False, 'error': 'No files uploaded'}), 400

        uploaded_files = request.files.getlist('files')

        combined_code = []

        for file in uploaded_files:
            filename = file.filename

            # Only analyze Python files
            if not filename.endswith('.py'):
                continue

            content = file.read().decode('utf-8', errors='ignore')

            # add filename markers (helps debugging)
            combined_code.append(f"\n# ===== FILE: {filename} =====\n")
            combined_code.append(content)

        if not combined_code:
            return jsonify({'success': False, 'error': 'No Python files found'}), 400

        full_program = "\n".join(combined_code)

        engine = MetaCodeEngine()
        report = engine.orchestrate(full_program)

        return jsonify({
            'success': True,
            'issues_count': len(report.issues),
            'report': "\n\n".join(report.issues)
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


# ---------------- Health ----------------
@app.route('/api/health')
def health():
    return jsonify({'status': 'ok'})


# ---------------- Run ----------------
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    app.run(host='0.0.0.0', port=port, debug=debug_mode)
