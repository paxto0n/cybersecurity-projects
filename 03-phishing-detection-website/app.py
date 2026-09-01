from flask import Flask, render_template, request
from detector import analyze_url_for_web

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", result=None)


@app.route("/check", methods=["POST"])
def check():
    url = request.form.get("url", "").strip()
    result = analyze_url_for_web(url) if url else None
    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
