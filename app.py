"""Flask app — SVG sanitizer for Wikimedia Commons."""

from flask import Flask, render_template, request, jsonify, Response
from sanitizer import sanitize_svg

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB cap


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/sanitize", methods=["POST"])
def sanitize():
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"error": "No file uploaded"}), 400

    raw = f.read()
    if not raw:
        return jsonify({"error": "Empty file"}), 400

    cleaned, issues = sanitize_svg(raw)

    if cleaned is None:
        return jsonify({
            "success": False,
            "issues": issues,
            "original_size": len(raw),
        })

    blocker_count = sum(1 for i in issues if i["severity"] == "blocker")
    warning_count = sum(1 for i in issues if i["severity"] == "warning")

    return jsonify({
        "success": True,
        "issues": issues,
        "blocker_count": blocker_count,
        "warning_count": warning_count,
        "cleaned": cleaned.decode("utf-8"),
        "original_size": len(raw),
        "cleaned_size": len(cleaned),
        "filename": f.filename,
    })


@app.errorhandler(413)
def too_big(e):
    return jsonify({"error": "File too large (10 MB max)"}), 413


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)