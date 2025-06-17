import re
import json
import hashlib
from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    send_from_directory,
    send_file,
    current_app,
    flash,
    jsonify,
    session,
)
from werkzeug.utils import secure_filename
from pathlib import Path
import pdfplumber

main = Blueprint("main", __name__)

ALLOWED_EXTENSIONS = {"pdf"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def load_rules():
    """Load all saved parsing rules from the rules folder."""
    rules = []
    rules_dir = current_app.config["RULES_FOLDER"]
    if not rules_dir.exists():
        return rules
    for path in rules_dir.glob("*.json"):
        try:
            rules.append(json.loads(path.read_text()))
        except Exception:
            continue
    return rules


def extract_text(path: Path) -> str:
    """Extract all text from a PDF using pdfplumber."""
    text_parts = []
    with pdfplumber.open(str(path)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            text_parts.append(page_text)
    return "\n".join(text_parts)


def metadata_hash(path: Path) -> str:
    """Return an MD5 hash of the PDF metadata."""
    with pdfplumber.open(str(path)) as pdf:
        meta = pdf.metadata or {}
    meta_str = json.dumps(meta, sort_keys=True)
    return hashlib.md5(meta_str.encode("utf-8")).hexdigest()


def text_fingerprint(text: str) -> str:
    """Return an MD5 hash of the first 100 words of the text."""
    words = re.findall(r"\w+", text)[:100]
    return hashlib.md5(" ".join(words).encode("utf-8")).hexdigest()


def parse_findings(text: str):
    """Parse findings from raw PDF text using simple heuristics."""
    findings = []
    current = {
        "title": "",
        "severity": "",
        "description": "",
        "remediation": "",
        "assets": "",
    }

    def commit():
        if any(v for v in current.values()):
            findings.append(current.copy())
            for k in current:
                current[k] = ""

    lines = [l.strip() for l in text.splitlines()]
    for line in lines:
        if not line:
            continue
        lower = line.lower()

        if re.match(r"^(\d+[\.)]|[-*\u2022])\s+", line) or re.search(
            r"\b(finding|vulnerability|security issue)\b", lower
        ):
            commit()
            current["title"] = line
            continue

        if lower.startswith("severity"):
            current["severity"] = line.split(":", 1)[-1].strip()
            continue
        if lower.startswith("description"):
            current["description"] += (" " + line.split(":", 1)[-1].strip()).strip()
            continue
        if lower.startswith("remediation") or lower.startswith("recommendation"):
            current["remediation"] += (" " + line.split(":", 1)[-1].strip()).strip()
            continue
        if lower.startswith("affected") or "asset" in lower or "url" in lower:
            text_value = line.split(":", 1)[-1].strip() if ":" in line else line
            current["assets"] += (" " + text_value).strip()
            continue

        if current["description"]:
            current["description"] += " " + line

    commit()
    return findings


@main.route("/", methods=["GET", "POST"])
def upload_file():
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files["file"]
        if file.filename == "":
            flash("No selected file")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_path = current_app.config["UPLOAD_FOLDER"] / filename
            data = file.read()
            file_hash = hashlib.md5(data).hexdigest()
            with open(upload_path, "wb") as f:
                f.write(data)

            text = extract_text(upload_path)
            fp_hash = text_fingerprint(text)
            meta_hash = metadata_hash(upload_path)
            with pdfplumber.open(str(upload_path)) as pdf:
                first_page = pdf.pages[0].extract_text() or ""

            rules = load_rules()
            matched = None
            for r in rules:
                if (
                    r.get("file_hash") == file_hash
                    or r.get("metadata_hash") == meta_hash
                    or r.get("fingerprint") == fp_hash
                ):
                    matched = r
                    break
                regex = r.get("regex")
                if regex and re.search(regex, first_page, re.IGNORECASE):
                    matched = r
                    break

            findings = parse_findings(text)
            columns = (
                matched.get("columns")
                if matched
                else ["title", "severity", "description", "remediation", "assets"]
            )

            session["raw_text"] = text
            session["findings"] = findings
            session["columns"] = columns
            session["file_hash"] = file_hash
            session["metadata_hash"] = meta_hash
            session["fingerprint"] = fp_hash
            flash("File uploaded and parsed successfully")
            return redirect(url_for("main.review"))
    return render_template("upload.html")


@main.route("/upload", methods=["POST"])
def api_upload():
    """API endpoint to upload a PDF and return parsed findings."""
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    if not file or not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400

    filename = secure_filename(file.filename)
    upload_path = current_app.config["UPLOAD_FOLDER"] / filename
    file.save(upload_path)

    text = extract_text(upload_path)
    findings = parse_findings(text)
    return jsonify({"findings": findings})


@main.route("/review")
def review():
    """Display a table for reviewing parsed findings."""
    findings = session.get("findings", [])
    raw_text = session.get("raw_text", "")
    columns = session.get(
        "columns", ["title", "severity", "description", "remediation", "assets"]
    )
    file_hash = session.get("file_hash", "")
    metadata_hash_value = session.get("metadata_hash", "")
    fingerprint = session.get("fingerprint", "")
    return render_template(
        "review.html",
        findings=findings,
        raw_text=raw_text,
        columns=columns,
        file_hash=file_hash,
        metadata_hash=metadata_hash_value,
        fingerprint=fingerprint,
    )


@main.route("/save_rule", methods=["POST"])
def save_rule():
    data = request.get_json()
    if not data or "name" not in data or "rule" not in data:
        return jsonify({"error": "Invalid data"}), 400
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", data["name"])
    rules_dir = current_app.config["RULES_FOLDER"]
    rules_dir.mkdir(exist_ok=True)
    rule = data["rule"]
    if "file_hash" not in rule:
        file_hash = session.get("file_hash")
        if file_hash:
            rule["file_hash"] = file_hash
    if "metadata_hash" not in rule:
        mh = session.get("metadata_hash")
        if mh:
            rule["metadata_hash"] = mh
    if "fingerprint" not in rule:
        fp = session.get("fingerprint")
        if fp:
            rule["fingerprint"] = fp
    path = rules_dir / f"{safe_name}.json"
    path.write_text(json.dumps(rule, indent=2))
    return jsonify({"status": "ok"})


@main.route("/csv_preview", methods=["GET", "POST"])
def csv_preview():
    """Allow final CSV tweaks and export."""
    if request.method == "POST":
        data = request.get_json()
        if not data or "columns" not in data or "rows" not in data:
            return jsonify({"error": "Invalid data"}), 400
        from io import StringIO, BytesIO
        import csv

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(data["columns"])
        for row in data["rows"]:
            writer.writerow(row)
        mem = BytesIO()
        mem.write(output.getvalue().encode("utf-8"))
        mem.seek(0)
        return send_file(
            mem, as_attachment=True, download_name="findings.csv", mimetype="text/csv"
        )
    findings = session.get("findings", [])
    columns = session.get(
        "columns", ["title", "severity", "description", "remediation", "assets"]
    )
    return render_template("csv_preview.html", findings=findings, columns=columns)


@main.route("/rules")
def list_rules():
    """Display existing parsing rules."""
    rules_dir = current_app.config["RULES_FOLDER"]
    names = [p.stem for p in rules_dir.glob("*.json")]
    return render_template("rules.html", names=names)


@main.route("/delete_rule", methods=["POST"])
def delete_rule():
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"error": "Invalid data"}), 400
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", data["name"])
    path = current_app.config["RULES_FOLDER"] / f"{safe_name}.json"
    if path.exists():
        path.unlink()
        return jsonify({"status": "deleted"})
    return jsonify({"error": "Rule not found"}), 404
