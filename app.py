import os
from flask import Flask, render_template, request, jsonify
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        code = data.get('code', '')

        if not code.strip():
            return jsonify({'success': False, 'error': 'No code'}), 400

        engine = MetaCodeEngine()
        report = engine.orchestrate(code)

        issues = report.issues
        complexity = report.complexity_metrics
        structure = report.structural_analysis
        resolutions = report.resolution_predictions

        return jsonify({
            'success': True,
            'clean': len(issues) == 0,
            'issues_count': len(issues),
            'report': '\n'.join(issues),
            'complexity': {
                'raw_size': complexity.get('raw_size', 0),
                'compressed_size': complexity.get('compressed_size', 0),
                'ratio': complexity.get('ratio', 0.0),
                'patterns': complexity.get('patterns', {}),
            },
            'structure': {
                'depth': structure.get('depth', 0),
                'branching_factor': structure.get('branching_factor', 0.0),
                'node_type_distribution': structure.get('node_type_distribution', {}),
            },
            'resolutions': [
                {
                    'issue': r.get('issue', ''),
                    'suggestion': r.get('suggestion', ''),
                    'convergence': r.get('convergence', False),
                }
                for r in resolutions
            ],
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'

    app.run(
        host='0.0.0.0',
        port=port,
        debug=debug_mode
    )
