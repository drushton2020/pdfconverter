import re
from flask import Blueprint, render_template, request, redirect, url_for, send_from_directory, current_app, flash, jsonify
from werkzeug.utils import secure_filename
from pathlib import Path
import pdfplumber

main = Blueprint('main', __name__)

ALLOWED_EXTENSIONS = {'pdf'}


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_text(path: Path) -> str:
    """Extract all text from a PDF using pdfplumber."""
    text_parts = []
    with pdfplumber.open(str(path)) as pdf:
        for page in pdf.pages:
            page_text = page.extract_text() or ""
            text_parts.append(page_text)
    return "\n".join(text_parts)


def parse_findings(text: str):
    """Parse findings from raw PDF text using simple heuristics."""
    findings = []
    current = {"title": "", "severity": "", "description": "", "remediation": "", "assets": ""}

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

        if re.match(r"^(\d+[\.)]|[-*\u2022])\s+", line) or re.search(r"\b(finding|vulnerability|security issue)\b", lower):
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


@main.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_path = current_app.config['UPLOAD_FOLDER'] / filename
            file.save(upload_path)
            flash('File uploaded successfully')
            return redirect(url_for('main.upload_file'))
    return render_template('upload.html')


@main.route('/upload', methods=['POST'])
def api_upload():
    """API endpoint to upload a PDF and return parsed findings."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if not file or not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400

    filename = secure_filename(file.filename)
    upload_path = current_app.config['UPLOAD_FOLDER'] / filename
    file.save(upload_path)

    text = extract_text(upload_path)
    findings = parse_findings(text)
    return jsonify({'findings': findings})
