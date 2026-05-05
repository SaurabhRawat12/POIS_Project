"""
CS8.401 Minicrypt Clique Explorer — Flask Backend
Entry point. Registers API blueprint, enables CORS for the React dev server.
"""
from flask import Flask, jsonify
from flask_cors import CORS

from api.routes import api_bp


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)  # open CORS for local dev; lock down later if deployed
    app.register_blueprint(api_bp, url_prefix="/api")

    @app.route("/")
    def root():
        return jsonify(
            {
                "name": "CS8.401 Minicrypt Clique Explorer — Backend",
                "version": "0.1.0",
                "stage": "PA#0 (scaffold with stubs)",
            }
        )

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=True)
