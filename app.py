from flask import Flask, render_template
from meta_code.dissonance import DissonanceDetector

app = Flask(__name__)

define_routes():
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/api/analyze', methods=['POST'])
    def analyze():
        # Implementation for analyze route
        return {'result': 'analyzed data'}

    @app.route('/api/health', methods=['GET'])
    def health():
        return {'status': 'healthy'}

if __name__ == '__main__':
    define_routes()
    app.run(host='0.0.0.0', port=5000)