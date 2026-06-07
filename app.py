import logging
import os
from pathlib import Path

from flask import Flask, render_template, request, send_from_directory, url_for

from main import CloudMisconfigurationScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "replace-with-secret")
app.config["OUTPUT_DIR"] = OUTPUT_DIR

try:
    from main import CloudMisconfigurationScanner

    scanner = CloudMisconfigurationScanner(output_dir=str(OUTPUT_DIR))
    scanner_init_error = None
except Exception as exc:
    scanner = None
    scanner_init_error = str(exc)
    logger.exception("Failed to initialize CloudMisconfigurationScanner")


@app.route("/", methods=["GET"])
def index():
    """Render the web-based scan form."""
    if scanner_init_error:
        return (
            f"<h1>Application initialization failed</h1><p>{scanner_init_error}</p>",
            500,
        )
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan_domain():
    """Run a scan and render the results page."""
    domain = request.form.get("domain", "").strip()
    format_option = request.form.get("format", "html")

    if not domain:
        return render_template(
            "index.html",
            error_message="Please enter a valid domain or hostname to scan.",
        )

    try:
        logger.info("Received web scan request for domain: %s", domain)
        scan_results = scanner.scan(domain)
        report_paths = scanner.generate_reports(scan_results, [format_option])

        report_links = {
            fmt: url_for("serve_report", filename=Path(path).name)
            for fmt, path in report_paths.items()
        }

        return render_template(
            "scan_results.html",
            domain=domain,
            scan_results=scan_results,
            report_links=report_links,
            format_option=format_option,
        )

    except Exception as exc:
        logger.exception("Failed to scan domain %s", domain)
        return render_template(
            "index.html",
            error_message=f"Scan failed: {exc}",
        )


@app.route("/reports/<path:filename>")
def serve_report(filename):
    """Serve generated report files from the output directory."""
    return send_from_directory(app.config["OUTPUT_DIR"], filename)


@app.route("/healthz", methods=["GET"])
def healthz():
    return "OK", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
