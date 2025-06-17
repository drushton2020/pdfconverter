from flask import Blueprint, render_template, request, redirect, url_for, send_from_directory, current_app, flash
from werkzeug.utils import secure_filename
from pathlib import Path

main = Blueprint('main', __name__)

ALLOWED_EXTENSIONS = {'pdf'}


def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
