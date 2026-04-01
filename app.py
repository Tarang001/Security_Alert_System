import os
from flask import Flask, request, jsonify, render_template
from services import enrich_ip
from utils import validate_ips, classify_ip

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    if not data or "ips" not in data:
        return jsonify({"error": "Provide JSON with 'ips' key"}), 400

    valid_ips, error = validate_ips(data["ips"])
    if error:
        return jsonify({"error": error}), 400

    results = []
    for ip in valid_ips:
        enriched = enrich_ip(ip)
        enriched["status"] = classify_ip(enriched)
        results.append(enriched)

    return jsonify({"results": results})


@app.route("/analyze-ui", methods=["POST"])
def analyze_ui():
    raw_input = request.form.get("ips", "")
    ip_list = [ip.strip() for ip in raw_input.split(",") if ip.strip()]

    valid_ips, error = validate_ips(ip_list)
    if error:
        return render_template("index.html", error=error)

    results = []
    for ip in valid_ips:
        enriched = enrich_ip(ip)
        enriched["status"] = classify_ip(enriched)
        results.append(enriched)

    return render_template("index.html", results=results)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)