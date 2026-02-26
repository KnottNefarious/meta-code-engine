from flask import Flask, render_template, request, jsonify
from meta_code.dissonance import DissonanceDetector

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
        detector = DissonanceDetector(code)
        detector.parse()
        detector.analyze()
        return jsonify({'success': True, 'clean': not detector.has_issues(), 'issues_count': len(detector.get_issues()), 'report': detector.report()})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)