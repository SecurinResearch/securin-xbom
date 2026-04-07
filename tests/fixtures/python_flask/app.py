"""Sample Flask app with auth — for testing."""

from flask import Flask, Blueprint, jsonify, request
from functools import wraps

app = Flask(__name__)

# Auth decorator
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

api = Blueprint("api", __name__, url_prefix="/api/v1")


@api.route("/health")
def health():
    return jsonify({"status": "ok"})


@api.route("/users", methods=["GET", "POST"])
@login_required
def users():
    if request.method == "POST":
        return jsonify({"created": True}), 201
    return jsonify({"users": []})


@api.route("/users/<int:user_id>", methods=["GET", "PUT", "DELETE"])
@login_required
def user_detail(user_id):
    return jsonify({"user_id": user_id})


@app.route("/admin/dashboard")
def admin_dashboard():
    return jsonify({"admin": True})


app.register_blueprint(api)
