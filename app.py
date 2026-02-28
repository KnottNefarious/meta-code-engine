from flask import Flask, request, jsonify, render_template
from meta_code.meta_engine import MetaCodeEngine

app = Flask(__name__)

engine = MetaCodeEngine()

# homepage
@app.route("/")
def index():
    return render_template("index.html")

# health check
@app.route("/health")
def health():
    return jsonify({"status": "alive"})

# DEBUG ROUTE (this is the key)
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(force=True)

        if not data or "code" not in data:
            return jsonify({
                "status": "error",
                "error": "No code received"
            }), 400

        code = data["code"]

        report = engine.orchestrate(code)

        return jsonify({
            "status": "ok",
            "issue_count": len(report.issues),
            "issues": report.issues
        })

    # THIS is what we need
    except Exception as e:
        import traceback
        return jsonify({
            "status": "crash",
            "error": str(e),
            "traceback": traceback.format_exc()
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
