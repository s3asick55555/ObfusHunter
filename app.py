from __future__ import annotations

from flask import Flask

from config import MAX_FILE_SIZE
from web.routes import web_blueprint


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE
    app.register_blueprint(web_blueprint)
    return app


if __name__ == "__main__":
    create_app().run(debug=True, host="0.0.0.0", port=5000)
