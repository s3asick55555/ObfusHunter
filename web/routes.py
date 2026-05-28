from __future__ import annotations

import time
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from analysis.engine import analyze_file
from config import REPORT_DIR, UPLOAD_DIR
from storage.report_store import load_report, save_report
from utils.files import allowed_file, safe_delete

web_blueprint = Blueprint("web", __name__)


def cleanup_old_files(root: Path, max_age_seconds: int = 3600) -> None:
    now = time.time()
    for item in root.glob("*"):
        try:
            if item.is_file() and now - item.stat().st_mtime > max_age_seconds:
                item.unlink()
        except OSError:
            pass


@web_blueprint.route("/")
def index():
    return render_template("index.html")


@web_blueprint.route("/api/analyze", methods=["POST"])
def analyze():
    cleanup_old_files(UPLOAD_DIR)
    cleanup_old_files(REPORT_DIR)

    if "file" not in request.files:
        return jsonify({"error": "No file field was provided."}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type."}), 400

    safe_name = secure_filename(file.filename)
    temp_path = UPLOAD_DIR / f"{int(time.time())}_{safe_name}"

    try:
        file.save(temp_path)
        result = analyze_file(str(temp_path))
        result["file"]["original_name"] = safe_name
        report_id = save_report(REPORT_DIR, result)
        result["report_id"] = report_id
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    finally:
        safe_delete(temp_path)


@web_blueprint.route("/api/report/<report_id>.json", methods=["GET"])
def download_report(report_id: str):
    data = load_report(REPORT_DIR, secure_filename(report_id))
    if not data:
        return jsonify({"error": "Report not found or expired."}), 404

    report_path = REPORT_DIR / f"{secure_filename(report_id)}.json"
    return send_file(
        report_path,
        mimetype="application/json",
        as_attachment=True,
        download_name="obfushunter_report.json",
    )
