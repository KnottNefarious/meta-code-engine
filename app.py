from flask import Flask, request, jsonify, render_template_string
from meta_code.meta_engine import MetaCodeEngine
import traceback

app = Flask(__name__)
engine = MetaCodeEngine()


PAGE = """
<!doctype html>
<html>
<head>
<title>Meta-Code Engine</title>
<style>
body { font-family: Arial; background:#0f172a; color:white; padding:20px; }
textarea { width:100%; height:240px; background:#020617; color:#e2e8f0; padding:10px; }
button { padding:12px 20px; margin-top:10px; background:#22c55e; border:none; color:black; font-weight:bold; cursor:pointer; }
pre { background:#020617; padding:15px; white-space:pre-wrap; }
.error { color:#f87171; }
</style>
</head>
<body>

<h1>Meta-Code Engine</h1>

<textarea id="code">
q = request.args.get("q")
return "<h1>" + q + "</h1>"
</textarea>

<br>
<button onclick="analyze()">Analyze Code</button>

<h2>Results</h2>
<pre id="output"></pre>

<script>
async function analyze(){
    const code = document.getElementById("code").value;

    const res = await fetch("/analyze",{
        method:"POST",
        headers:{"Content-Type":"text/plain"},
        body:code
    });

    const data = await res.json();

    const out = document.getElementById("output");

    if(data.error){
        out.innerHTML = "SERVER ERROR:\\n" + data.error + "\\n\\n" + (data.trace || "");
        return;
    }

    let text = "Issues Found: " + data.issues_found + "\\n\\n";
    text += data.report.join("\\n\\n");
    out.textContent = text;
}
</script>

</body>
</html>
"""


@app.route("/")
def home():
    return render_template_string(PAGE)


@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        # Accept both raw text and JSON
        if request.is_json:
            user_code = request.json.get("code", "")
        else:
            user_code = request.data.decode("utf-8")

        if not user_code.strip():
            return jsonify({"error":"No code provided"}), 400

        report = engine.orchestrate(user_code)

        return jsonify({
            "issues_found": len(report.issues),
            "report": report.issues
        })

    except Exception as e:
        return jsonify({
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)
