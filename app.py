from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_dance.contrib.google import make_google_blueprint, google
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------
# App Setup
# ----------------------------
app = Flask(__name__)
app.secret_key = os.urandom(24)

# ----------------------------
# Database Setup
# ----------------------------
def init_db():
    with sqlite3.connect("users.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                provider TEXT DEFAULT 'normal'
            )
        """)
init_db()

# ----------------------------
# Google OAuth Setup
# ----------------------------
google_bp = make_google_blueprint(
    client_id="YOUR_GOOGLE_CLIENT_ID",       # Replace with your Google Client ID
    client_secret="YOUR_GOOGLE_CLIENT_SECRET", # Replace with your Google Client Secret
    scope=["profile", "email"],
    redirect_to="google_login"
)
app.register_blueprint(google_bp, url_prefix="/login")

# ----------------------------
# Routes
# ----------------------------
@app.route("/")
def index():
    return render_template("index.html")

# ----------------------------
# Signup Route
# ----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    hashed_password = generate_password_hash(password)

    try:
        with sqlite3.connect("users.db") as conn:
            conn.execute(
                "INSERT INTO users (email, password, provider) VALUES (?, ?, ?)",
                (email, hashed_password, "normal")
            )
        return redirect("/login")
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Email already exists"}), 409

# ----------------------------
# Login Route
# ----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    # JSON POST from JS fetch
    if request.is_json:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")
    else:
        email = request.form.get("email")
        password = request.form.get("password")

    if not email or not password:
        return jsonify({"success": False, "message": "All fields required"}), 400

    with sqlite3.connect("users.db") as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    if user["provider"] != "normal":
        return jsonify({"success": False, "message": f"Please login with {user['provider']}"}), 400

    if check_password_hash(user["password"], password):
        session["user"] = email
        return jsonify({"success": True})

    return jsonify({"success": False, "message": "Invalid credentials"}), 401

# ----------------------------
# Google OAuth Login
# ----------------------------
@app.route("/google-login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    if not resp.ok:
        return "Google login failed", 400

    info = resp.json()
    email = info["email"]

    # Check if user exists in DB
    with sqlite3.connect("users.db") as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

    if not user:
        with sqlite3.connect("users.db") as conn:
            conn.execute(
                "INSERT INTO users (email, provider) VALUES (?, ?)",
                (email, "google")
            )

    session["user"] = email
    return redirect("/home")

# ----------------------------
# Home Route (Protected)
# ----------------------------
@app.route("/home")
def home():
    if "user" not in session:
        return redirect("/login")
    return render_template("home.html", email=session["user"])

# ----------------------------
# Logout
# ----------------------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")

# ----------------------------
# Run App
# ----------------------------
if __name__ == "__main__":
    app.run(debug=True)