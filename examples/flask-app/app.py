"""Minimal Flask application for forgeseal Python lockfile demo."""

from flask import Flask

app = Flask(__name__)


@app.route("/")
def hello():
    return "Hello from flask-demo!"


if __name__ == "__main__":
    app.run(debug=True)
