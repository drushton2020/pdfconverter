from flask import Flask
from pathlib import Path

UPLOAD_FOLDER = Path('uploads')
UPLOAD_FOLDER.mkdir(exist_ok=True)
RULES_FOLDER = Path('rules')
RULES_FOLDER.mkdir(exist_ok=True)

def create_app():
    app = Flask(__name__)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    app.config['RULES_FOLDER'] = RULES_FOLDER
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
    app.secret_key = 'dev'

    from .routes import main
    app.register_blueprint(main)
    return app
