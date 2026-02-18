from flask import Flask, request, jsonify, render_template
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# -----------------------------
# Create Database & Table
# -----------------------------
def init_db():
    conn = sqlite3.connect("users.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()


# -----------------------------
# HOME ROUTE (Fix 404)
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------
# SIGNUP PAGE (GET)
# -----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():

    # If browser opens page
    if request.method == "GET":
        return render_template("signup.html")

    # If fetch() sends POST
    data = request.get_json()

    username = data["username"]
    email = data["email"]
    password = data["password"]

    hashed_password = generate_password_hash(password)

    try:
        conn = sqlite3.connect("users.db")
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )
        conn.commit()
        conn.close()

        return jsonify({"success": True})

    except sqlite3.IntegrityError:
        return jsonify({
            "success": False,
            "message": "Email already exists"
        })


# -----------------------------
# LOGIN PAGE
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json()

    email = data["email"]
    password = data["password"]

    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user["password"], password):
        return jsonify({"success": True})
        return render_template("home.html")
    else:
        return jsonify({
            "success": False,
            "message": "Invalid credentials"
        })

@app.route("/home")
def home_page():
    return render_template("home.html")


if __name__ == "__main__":
    app.run(debug=True)
