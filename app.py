import threading

from flask import Flask, jsonify, render_template

import config
from scanner import load_cached_results, scan_mailbox

app = Flask(__name__)

scan_status = {"running": False, "progress": 0, "total": 0, "message": ""}


def progress_callback(current, total, message):
    scan_status["progress"] = current
    scan_status["total"] = total
    scan_status["message"] = message


@app.route("/")
def index():
    configured = bool(config.IMAP_HOST and config.IMAP_USER and config.IMAP_PASSWORD)
    cached = load_cached_results()
    return render_template("index.html", configured=configured, cached=cached)


@app.route("/scan", methods=["POST"])
def start_scan():
    if scan_status["running"]:
        return jsonify({"error": "Scan already in progress"}), 409

    def run_scan():
        scan_status["running"] = True
        scan_status["progress"] = 0
        scan_status["total"] = 0
        scan_status["message"] = "Connecting..."
        try:
            scan_mailbox(progress_callback=progress_callback)
            scan_status["message"] = "Complete"
        except Exception as e:
            scan_status["message"] = f"Error: {e}"
        finally:
            scan_status["running"] = False

    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    return jsonify({"status": "started"})


@app.route("/scan/status")
def get_scan_status():
    return jsonify(scan_status)


@app.route("/results")
def get_results():
    cached = load_cached_results()
    if cached:
        return jsonify(cached)
    return jsonify({"error": "No results yet"}), 404


if __name__ == "__main__":
    app.run(debug=True, port=5000)
