"""PhishGuard Flask app: Frontend -> Flask -> Detection -> Risk Engine -> SQLite."""
import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, abort

import database
from risk_engine import scan_message, scan_url

MAX_TEXT = 10000
MAX_URL = 2048

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64 KB request limit

database.init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    input_type = request.form.get("input_type", "")
    text = (request.form.get("input_text") or "").strip()

    if input_type not in ("email", "url"):
        flash("Invalid scan type.", "error")
        return redirect(url_for("index"))
    if not text:
        flash("Please enter something to scan.", "error")
        return redirect(url_for("index"))
    limit = MAX_URL if input_type == "url" else MAX_TEXT
    if len(text) > limit:
        flash(f"Input is too long (max {limit} characters).", "error")
        return redirect(url_for("index"))
    if input_type == "url" and any(c.isspace() for c in text):
        flash("A URL cannot contain spaces.", "error")
        return redirect(url_for("index"))

    try:
        result = scan_url(text) if input_type == "url" else scan_message(text)
        scan_id = database.save_scan(input_type, text, result)
    except FileNotFoundError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception:
        app.logger.exception("Scan failed")
        flash("Something went wrong while scanning. Please try again.", "error")
        return redirect(url_for("index"))
    return redirect(url_for("result", scan_id=scan_id))


@app.route("/result/<int:scan_id>")
def result(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        abort(404)
    return render_template("result.html", scan=scan)


@app.route("/history")
def history():
    return render_template("history.html", scans=database.get_history())


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", stats=database.get_stats(),
                           recent=database.get_history(5))


@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", message="Page not found."), 404


@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", message="Request too large."), 413


@app.errorhandler(500)
def server_error(_):
    return render_template("error.html", message="Internal server error."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
