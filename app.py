import os
import json
import hashlib
from datetime import datetime

import requests
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

from email_parser import parse_eml_file
from risk_engine import calculate_risk
from db import init_db, save_case


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
ALLOWED_EXTENSIONS = {"eml"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["REPORT_FOLDER"] = REPORT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

init_db()

GEO_API_URL = "http://ip-api.com/json/{ip}"


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_ip_location(ip):
    try:
        resp = requests.get(GEO_API_URL.format(ip=ip), timeout=5)
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            print(f"Geolocation API error for {ip}: {data.get('message')}")
            return None
        return {
            "ip": ip,
            "city": data.get("city"),
            "region": data.get("regionName"),
            "country": data.get("country"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "org": data.get("org"),
        }
    except Exception as e:
        print(f"Geolocation failed for {ip}: {e}")
        return None


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/map")
def map_page():
    return render_template("map.html")


@app.route("/analyze", methods=["POST"])
def analyze_email():
    if "email_file" not in request.files:
        return jsonify({
            "success": False,
            "error": "Please upload an .eml file."
        }), 400

    uploaded_file = request.files["email_file"]

    if uploaded_file.filename == "":
        return jsonify({
            "success": False,
            "error": "No file selected."
        }), 400

    if not allowed_file(uploaded_file.filename):
        return jsonify({
            "success": False,
            "error": "Only .eml files are supported."
        }), 400

    try:
        safe_filename = secure_filename(uploaded_file.filename)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        case_id = f"MT-{timestamp}"

        saved_filename = f"{case_id}_{safe_filename}"
        saved_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            saved_filename
        )

        uploaded_file.save(saved_path)

        with open(saved_path, "rb") as email_file:
            evidence_hash = hashlib.sha256(email_file.read()).hexdigest()

        email_data = parse_eml_file(saved_path)
        risk_data = calculate_risk(email_data)

        ips = email_data.get("ips_found", [])
        print("IPS FOUND:", ips)

        result = {
            "success": True,
            "case_id": case_id,
            "analysis_time": datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            "original_filename": safe_filename,
            "evidence_sha256": evidence_hash,
            "email_data": email_data,
            "risk_analysis": risk_data,
            "ips": ips,
            "report_url": f"/report/{case_id}"
        }

        save_case(
            case_id=case_id,
            original_filename=safe_filename,
            risk_score=risk_data.get("risk_score", 0),
            threat_category=risk_data.get("threat_category", ""),
            ips=ips,
            evidence_sha256=evidence_hash,
        )

        report_path = os.path.join(
            app.config["REPORT_FOLDER"],
            f"{case_id}.json"
        )

        with open(report_path, "w", encoding="utf-8") as report_file:
            json.dump(
                result,
                report_file,
                indent=4,
                ensure_ascii=False
            )

        return jsonify(result)

    except Exception as error:
        return jsonify({
            "success": False,
            "error": f"Unable to analyze email: {str(error)}"
        }), 500


@app.route("/geolocate_ips", methods=["POST"])
def geolocate_ips():
    ips = request.get_json()

    if not isinstance(ips, list):
        return jsonify({"error": "Expected a JSON array of IP strings."}), 400

    results = []
    for ip in ips:
        info = get_ip_location(ip)
        if info:
            results.append(info)

    return jsonify(results)


@app.route("/report/<case_id>")
def download_report(case_id):
    report_path = os.path.join(
        app.config["REPORT_FOLDER"],
        f"{case_id}.json"
    )

    if not os.path.exists(report_path):
        return jsonify({
            "success": False,
            "error": "Report not found."
        }), 404

    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"{case_id}_forensic_report.json",
        mimetype="application/json"
    )


@app.errorhandler(413)
def file_too_large(error):
    return jsonify({
        "success": False,
        "error": "File is too large. Maximum allowed size is 10 MB."
    }), 413


if __name__ == "__main__":
    app.run(debug=True)
