from google_auth_oauthlib.flow import Flow
import os
import re  # For password validation : regex
import pathlib
import requests
import random
import time
import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for,session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()
os.getenv("OAUTHLIB_INSECURE_TRANSPORT")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

GOOGLE_CLIENT_SECRETS_FILE = os.getenv("GOOGLE_CLIENT_SECRETS_FILE")

SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid"
]

REDIRECT_URI = os.getenv("REDIRECT_URI")

DATABASE = "database.db"

# -------------------------------
# Create Database & Table
# -------------------------------
def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT,
            provider TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()

init_db()

@app.route("/")
def index():
    return render_template("index.html")

# -------------------------------
# Register Route
# -------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'

        if not re.match(password_pattern, password):
            return render_template(
                "signup.html",
                email=email,
                error="Password must be at least 8 characters and include uppercase, lowercase, number and special character."
            )

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO users (email, password, provider)
                VALUES (?, ?, ?)
            """, (email, hashed_password, "signup"))

            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template(
                "signup.html",
                email=email,
                error="Email already exists. Please use a different email or sign in."
            )

        conn.close()
        return redirect("/signin")

    return render_template("signup.html")

# -------------------------------
# Login Route
# -------------------------------
@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        conn.close()

        if user:
            stored_password = user[0]

            if check_password_hash(stored_password, password):
                session["user"] = email
                session["provider"] = "signup"
                return redirect("/home")
            else:
                return render_template("signin.html", error="Incorrect password!")
        else:
            return render_template("signin.html", error="Email does not exist! Please sign up first.")

    return render_template("signin.html")    

# -------------------------------
# Forgot Password - Step 1 (Enter Email)
# -------------------------------
@app.route("/forgotpass", methods=["GET", "POST"])
def forgotpass():

    if request.method == "POST":
        email = request.form["email"]

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        conn.close()

        if user:
            otp = random.randint(100000, 999999)
            session["reset_email"] = email
            session["otp"] = str(otp)
            session["otp_time"] = time.time()
            session["resend_count"] = 0

            send_otp(email, otp)
            return redirect(url_for("verify_otp"))
        else:
            return render_template("forgotpass.html", error="Email does not exist!")

    return render_template("forgotpass.html")


# -------------------------------
# Reset Password - Step 2 (New Password)
# -------------------------------
@app.route("/resetpass", methods=["GET", "POST"])
def resetpass():
    if "reset_email" not in session:
        return redirect(url_for("forgotpass"))

    email = session["reset_email"]

    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        if new_password != confirm_password:
            return render_template("resetpass.html", email=email, error="Passwords do not match!")
    
        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_pattern, new_password):
            return render_template(
                "resetpass.html",
                email=email,
                error="Password must be at least 8 characters and include uppercase, lowercase, number and special character."
            )

        hashed_password = generate_password_hash(new_password)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users
            SET password = ?
            WHERE email = ?
        """, (hashed_password, email))

        conn.commit()
        conn.close()

        session.pop("otp", None)
        session.pop("reset_email", None)
        session["user"] = email
        return redirect(url_for("home"))

    return render_template("resetpass.html", email=email)

# -------------------------------
# Google Login
# -------------------------------
@app.route("/google-login")
def google_login():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

    authorization_url, state = flow.authorization_url()

    return redirect(authorization_url)

@app.route("/callback")
def callback():

    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    userinfo_endpoint = "https://www.googleapis.com/oauth2/v1/userinfo"
    response = requests.get(userinfo_endpoint, params={
        "access_token": credentials.token
    })

    user_info = response.json()
    email = user_info["email"]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        cursor.execute("""
            INSERT INTO users (email, password, provider)
            VALUES (?, ?, ?)
        """, (email, None, "google"))
        conn.commit()

        session["reset_email"] = email
        conn.close()
        return redirect(url_for("resetpass"))

    cursor.execute("SELECT password FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()

    if row is None or row[0] is None:
        session["reset_email"] = email
        conn.close()
        return redirect(url_for("resetpass"))  

    conn.close()

    session["user"] = email
    session["provider"] = "google"

    return redirect(url_for("home"))
    
# -------------------------------
# OTP Email Sender
# -------------------------------

def send_otp(to_email, otp):
    sender_email = os.getenv("EMAIL_USER")
    sender_password = os.getenv("EMAIL_PASS")

    print("DEBUG EMAIL:", sender_email)
    print("DEBUG PASS:", sender_password)

    msg = MIMEText(f"Your OTP for password reset is: {otp}")
    msg["Subject"] = "Password Reset OTP"
    msg["From"] = sender_email
    msg["To"] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.send_message(msg)
    server.quit()

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    if request.method == "POST":
        user_otp = request.form["otp"]

        if time.time() - session.get("otp_time", 0) > 300:
            return render_template("verify_otp.html", error="OTP Expired")

        if user_otp == session.get("otp"):
            return redirect(url_for("resetpass"))
        else:
            return render_template("verify_otp.html", error="Invalid OTP")

    return render_template("verify_otp.html")

# -------------------------------
# Resend OTP Route
# -------------------------------

@app.route("/resend_otp")
def resend_otp():

    if "reset_email" not in session:
        return redirect(url_for("forgotpass"))

    # Limit resend attempts
    if session.get("resend_count", 0) >= 3:
        return "Maximum resend attempts reached."

    # Prevent resend before 30 seconds
    if time.time() - session.get("otp_time", 0) < 30:
        return "Please wait before requesting again."

    email = session["reset_email"]
    otp = random.randint(100000, 999999)

    session["otp"] = str(otp)
    session["otp_time"] = time.time()
    session["resend_count"] += 1

    send_otp(email, otp)

    return redirect(url_for("verify_otp"))

# -------------------------------
# Home Route (FIXED)
# -------------------------------
@app.route("/home")
def home():
    if "user" not in session:
        return redirect(url_for("signin"))

    return render_template("home.html", email=session["user"])

@app.route("/logout")
def logout():
    session.clear()   # removes all session data
    return redirect(url_for("index"))    


if __name__ == "__main__":
    app.run(debug=True)