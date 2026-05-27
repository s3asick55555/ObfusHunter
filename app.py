#!/usr/bin/env python3
"""
Unified Flask web application for defensive static analysis of PE-like binaries.
"""

from __future__ import annotations

import csv
import io
import json
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from analysis_engine import analyze_binary


APP_ROOT = Path(__file__).resolve().parent
UPLOAD_FOLDER = APP_ROOT / "uploads"
REPORT_FOLDER = APP_ROOT / "reports"
ALLOWED_EXTENSIONS = {"exe", "bin", "dll", "scr", "sys", "com"}
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MiB

UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORT_FOLDER.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


def allowed_file(filename: str) -> bool:
    """Allow PE-like samples and raw binaries."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def cleanup_old_uploads(max_age_seconds: int = 3600) -> None:
    """Remove old temporary upload files and saved reports."""
    now = time.time()
    for folder in (UPLOAD_FOLDER, REPORT_FOLDER):
        for item in folder.glob("*"):
            try:
                if item.is_file() and now - item.stat().st_mtime > max_age_seconds:
                    item.unlink()
            except OSError:
                pass


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    cleanup_old_uploads()

    if "file" not in request.files:
        return jsonify({"error": "No file field was provided."}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        return jsonify({
            "error": "Invalid file type.",
            "allowed_extensions": sorted(ALLOWED_EXTENSIONS),
        }), 400

    safe_original = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex}_{safe_original}"
    filepath = UPLOAD_FOLDER / unique_name

    try:
        file.save(filepath)
        result = analyze_binary(str(filepath))
        result["original_filename"] = safe_original

        report_id = uuid.uuid4().hex
        report_path = REPORT_FOLDER / f"{report_id}.json"
        report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        result["report_id"] = report_id

        return jsonify(result)

    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    finally:
        try:
            filepath.unlink(missing_ok=True)
        except OSError:
            pass


@app.route("/api/report/<report_id>.json", methods=["GET"])
def download_json_report(report_id: str):
    report_path = REPORT_FOLDER / f"{secure_filename(report_id)}.json"
    if not report_path.exists():
        return jsonify({"error": "Report not found or expired."}), 404

    return send_file(
        report_path,
        mimetype="application/json",
        as_attachment=True,
        download_name="obfuscation_report.json",
    )


@app.route("/api/report/<report_id>.csv", methods=["GET"])
def download_feature_csv(report_id: str):
    report_path = REPORT_FOLDER / f"{secure_filename(report_id)}.json"
    if not report_path.exists():
        return jsonify({"error": "Report not found or expired."}), 404

    data = json.loads(report_path.read_text(encoding="utf-8"))
    features = data.get("features", {})

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(features.keys()))
    writer.writeheader()
    writer.writerow(features)

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)

    return send_file(
        mem,
        mimetype="text/csv",
        as_attachment=True,
        download_name="ml_features.csv",
    )


@app.template_filter("format_bytes")
def format_bytes(bytes_val):
    try:
        bytes_val = float(bytes_val)
    except Exception:
        return bytes_val

    for unit in ["B", "KB", "MB"]:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024

    return f"{bytes_val:.2f} GB"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
