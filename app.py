from flask import Flask, redirect, session, send_from_directory, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector
from urllib.parse import urlsplit, unquote
from email.message import EmailMessage
import smtplib
import requests
import os
from datetime import datetime, timezone

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# =========================================================
# MYSQL / LOCAL EMAIL-PASSWORD LOGIN
# =========================================================

def get_db_connection():
    """
    Connect to Railway MySQL using MYSQL_PUBLIC_URL.

    Expected format:
        mysql://USERNAME:PASSWORD@HOST:PORT/DATABASE

    The URL is read from Render's environment variables and is
    never hard-coded into the source code.
    """
    database_url = os.getenv("MYSQL_PUBLIC_URL")

    if not database_url:
        raise RuntimeError("MYSQL_PUBLIC_URL is not configured.")

    parsed = urlsplit(database_url)

    if not parsed.hostname:
        raise RuntimeError("MYSQL_PUBLIC_URL is invalid: missing host.")

    database = parsed.path.lstrip("/")
    if not database:
        raise RuntimeError("MYSQL_PUBLIC_URL is invalid: missing database name.")

    return mysql.connector.connect(
        host=parsed.hostname,
        port=parsed.port or 3306,
        user=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
        database=unquote(database),
        connection_timeout=15,
    )


def ensure_users_table():
    """
    Makes the local-login table available if it does not already exist.
    """
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            )
        """)
        connection.commit()
        cursor.close()
        connection.close()
        print("✅ MySQL users table is ready.")
    except Exception as error:
        print("⚠️ MySQL startup check failed:", error)


def create_local_session(user_id, email):
    session["user"] = {
        "provider": "Email",
        "id": str(user_id),
        "name": email.split("@", 1)[0],
        "email": email,
        "picture": None,
    }


oauth = OAuth(app)


# =========================================================
# EMAIL LOGIN ALERT
# =========================================================

def send_login_alert(user):
    smtp_email = os.getenv("ALERT_EMAIL")
    smtp_password = os.getenv("ALERT_EMAIL_PASSWORD")
    alert_to = os.getenv("ALERT_TO_EMAIL")

    if not smtp_email or not smtp_password or not alert_to:
        print("Login alert email is not configured.")
        return

    login_time = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    username = user.get("name") or "Unknown"
    email = user.get("email") or "Not provided"
    provider = user.get("provider") or "Unknown"
    user_id = user.get("id") or "Unknown"

    message = EmailMessage()

    message["Subject"] = "Web-2 New Login Alert"
    message["From"] = smtp_email
    message["To"] = alert_to

    message.set_content(
        f"""Web-2 Login Alert

A new login was completed on your website.

Username: {username}
Email: {email}
Login provider: {provider}
Account ID: {user_id}
Login time: {login_time}

IMPORTANT:
The user's provider password is NOT collected, stored, or sent by Web-2.

If this login was not expected, secure the corresponding
Google or Discord account from the official provider website.
"""
    )

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.send_message(message)

        print("Login alert email sent.")

    except Exception as error:
        print("Could not send login alert:", error)



# =========================================================
# EMAIL/PASSWORD LOGIN
# =========================================================

@app.route("/login")
def local_login_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Web-2 Login</title>
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                min-height: 100vh;
                background: #020617;
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .box {
                width: 430px;
                max-width: 100%;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 24px;
                padding: 32px;
                box-shadow: 0 25px 80px rgba(0,0,0,.55);
            }
            h1 { margin: 0 0 8px; }
            p { color: #94a3b8; }
            label {
                display: block;
                margin: 18px 0 8px;
                color: #cbd5e1;
                font-weight: bold;
            }
            input {
                width: 100%;
                padding: 13px 14px;
                border-radius: 10px;
                border: 1px solid #475569;
                background: #020617;
                color: white;
                outline: none;
            }
            button, a {
                display: block;
                width: 100%;
                margin-top: 16px;
                padding: 13px 14px;
                border-radius: 10px;
                border: 0;
                text-align: center;
                text-decoration: none;
                cursor: pointer;
                font-weight: bold;
            }
            button {
                background: #2563eb;
                color: white;
            }
            .secondary {
                background: #1e293b;
                color: white;
                border: 1px solid #475569;
            }
            .divider {
                text-align: center;
                color: #64748b;
                margin: 18px 0;
            }
            .small {
                font-size: 13px;
                color: #64748b;
                margin-top: 14px;
            }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>Sign in to Web-2</h1>
            <p>Use your Web-2 account email and password.</p>

            <form method="POST" action="/login/email">
                <label for="email">Email</label>
                <input id="email" name="email" type="email" autocomplete="email" required>

                <label for="password">Password</label>
                <input id="password" name="password" type="password"
                       autocomplete="current-password" required>

                <button type="submit">Sign in with Email</button>
            </form>

            <div class="divider">or</div>

            <a class="secondary" href="/login/google">Continue with Google</a>
            <a class="secondary" href="/login/discord">Continue with Discord</a>

            <a class="secondary" href="/register">Create a Web-2 account</a>

            <div class="small">
                Web-2 never stores your email-account provider password.
            </div>
        </div>
    </body>
    </html>
    """


@app.route("/register")
def register_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Create Web-2 Account</title>
        <style>
            * { box-sizing: border-box; }
            body {
                margin: 0;
                min-height: 100vh;
                background: #020617;
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .box {
                width: 430px;
                max-width: 100%;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 24px;
                padding: 32px;
            }
            h1 { margin: 0 0 8px; }
            p { color: #94a3b8; }
            label {
                display: block;
                margin: 18px 0 8px;
                color: #cbd5e1;
                font-weight: bold;
            }
            input {
                width: 100%;
                padding: 13px 14px;
                border-radius: 10px;
                border: 1px solid #475569;
                background: #020617;
                color: white;
            }
            button, a {
                display: block;
                width: 100%;
                margin-top: 16px;
                padding: 13px 14px;
                border-radius: 10px;
                border: 0;
                text-align: center;
                text-decoration: none;
                cursor: pointer;
                font-weight: bold;
            }
            button { background: #2563eb; color: white; }
            a {
                background: #1e293b;
                color: white;
                border: 1px solid #475569;
            }
            .small {
                font-size: 13px;
                color: #64748b;
                margin-top: 14px;
            }
        </style>
    </head>
    <body>
        <div class="box">
            <h1>Create Web-2 account</h1>
            <p>Your password will be stored only as a secure hash.</p>

            <form method="POST" action="/register">
                <label for="email">Email</label>
                <input id="email" name="email" type="email"
                       autocomplete="email" required>

                <label for="password">Password</label>
                <input id="password" name="password" type="password"
                       minlength="8" autocomplete="new-password" required>

                <label for="confirm_password">Confirm password</label>
                <input id="confirm_password" name="confirm_password"
                       type="password" minlength="8"
                       autocomplete="new-password" required>

                <button type="submit">Create account</button>
            </form>

            <a href="/login">Back to login</a>

            <div class="small">
                Do not reuse a password that you use for another important account.
            </div>
        </div>
    </body>
    </html>
    """


@app.post("/register")
def register():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not email or "@" not in email:
        return "Please enter a valid email address.", 400

    if len(password) < 8:
        return "Password must be at least 8 characters.", 400

    if password != confirm_password:
        return "Passwords do not match.", 400

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE email = %s",
            (email,)
        )

        if cursor.fetchone():
            cursor.close()
            connection.close()
            return """
                <h1>Account already exists</h1>
                <p>This email already has a Web-2 account.</p>
                <a href="/login">Go to login</a>
            """, 409

        password_hash = generate_password_hash(password)

        cursor.execute(
            """
            INSERT INTO users (email, password_hash)
            VALUES (%s, %s)
            """,
            (email, password_hash)
        )

        connection.commit()
        user_id = cursor.lastrowid

        cursor.close()
        connection.close()

        create_local_session(user_id, email)
        send_login_alert(session["user"])

        return redirect("/account")

    except Exception as error:
        print("Local registration error:", error)
        return """
            <h1>Registration error</h1>
            <p>The database connection could not complete the request.</p>
            <a href="/register">Try again</a>
        """, 500


@app.post("/login/email")
def email_login():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not email or not password:
        return "Email and password are required.", 400

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, email, password_hash
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        if not user or not check_password_hash(
            user["password_hash"],
            password
        ):
            cursor.close()
            connection.close()
            return """
                <h1>Login failed</h1>
                <p>Invalid email or password.</p>
                <a href="/login">Try again</a>
            """, 401

        cursor.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s",
            (user["id"],)
        )
        connection.commit()

        cursor.close()
        connection.close()

        create_local_session(user["id"], user["email"])
        send_login_alert(session["user"])

        return redirect("/account")

    except Exception as error:
        print("Local login error:", error)
        return """
            <h1>Login error</h1>
            <p>The database connection could not complete the request.</p>
            <a href="/login">Try again</a>
        """, 500


# =========================================================
# GOOGLE
# =========================================================

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url=(
        "https://accounts.google.com/.well-known/openid-configuration"
    ),
    client_kwargs={
        "scope": "openid email profile"
    }
)


@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/login/google")
def google_login():
    redirect_uri = (
        os.getenv("GOOGLE_REDIRECT_URI")
        or "http://127.0.0.1:5000/auth/google/callback"
    )

    return google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def google_callback():
    try:
        token = google.authorize_access_token()

        user = token.get("userinfo")

        if not user:
            return "Google did not return user information.", 400

        session["user"] = {
            "provider": "Google",
            "id": user.get("sub"),
            "name": user.get("name"),
            "email": user.get("email"),
            "picture": user.get("picture")
        }

        send_login_alert(session["user"])

        return redirect("/account")

    except Exception as error:
        return f"""
        <h1>Google Login Error</h1>
        <pre>{error}</pre>
        """, 500


# =========================================================
# DISCORD
# =========================================================

@app.route("/login/discord")
def discord_login():

    client_id = os.getenv("DISCORD_CLIENT_ID")

    redirect_uri = (
        os.getenv("DISCORD_REDIRECT_URI")
        or "http://127.0.0.1:5000/auth/discord/callback"
    )

    discord_url = (
        "https://discord.com/oauth2/authorize"
        "?client_id=" + client_id +
        "&response_type=code"
        "&redirect_uri=" +
        requests.utils.quote(redirect_uri, safe="") +
        "&scope=identify%20email"
    )

    return redirect(discord_url)


@app.route("/auth/discord/callback")
def discord_callback():

    code = request.args.get("code")

    if not code:
        error = request.args.get("error")

        return f"""
        <h1>Discord Login Cancelled</h1>
        <p>{error or "No authorization code was returned."}</p>
        """, 400

    client_id = os.getenv("DISCORD_CLIENT_ID")
    client_secret = os.getenv("DISCORD_CLIENT_SECRET")

    redirect_uri = (
        os.getenv("DISCORD_REDIRECT_URI")
        or "http://127.0.0.1:5000/auth/discord/callback"
    )

    token_response = requests.post(
        "https://discord.com/api/v10/oauth2/token",

        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri
        },

        headers={
            "Content-Type": "application/x-www-form-urlencoded"
        },

        auth=(client_id, client_secret),

        timeout=15
    )

    if token_response.status_code != 200:

        return f"""
        <h1>Discord Token Error</h1>
        <p>Status: {token_response.status_code}</p>
        <pre>{token_response.text}</pre>
        """, 400

    token = token_response.json()

    access_token = token.get("access_token")

    if not access_token:
        return "Discord did not return an access token.", 400

    user_response = requests.get(
        "https://discord.com/api/v10/users/@me",

        headers={
            "Authorization": f"Bearer {access_token}"
        },

        timeout=15
    )

    if user_response.status_code != 200:

        return f"""
        <h1>Discord User Error</h1>
        <p>Status: {user_response.status_code}</p>
        <pre>{user_response.text}</pre>
        """, 400

    user = user_response.json()

    picture = None

    if user.get("avatar"):

        picture = (
            "https://cdn.discordapp.com/avatars/"
            f"{user['id']}/{user['avatar']}.png"
        )

    session["user"] = {
        "provider": "Discord",
        "id": user.get("id"),
        "name": (
            user.get("global_name")
            or user.get("username")
            or "Discord User"
        ),
        "email": user.get("email"),
        "picture": picture
    }

    send_login_alert(session["user"])

    return redirect("/account")


# =========================================================
# ACCOUNT
# =========================================================

@app.route("/account")
def account():

    user = session.get("user")

    if not user:
        return redirect("/")

    picture = user.get("picture")

    if picture:

        image_html = f"""
        <img src="{picture}" alt="Profile">
        """

    else:

        image_html = """
        <div class="avatar">👤</div>
        """

    return f"""
    <!DOCTYPE html>

    <html>

    <head>

        <title>Web-2 Account</title>

        <style>

            body {{
                margin: 0;
                min-height: 100vh;
                background: #020617;
                color: white;
                font-family: Arial, sans-serif;
                display: flex;
                justify-content: center;
                align-items: center;
            }}

            .box {{
                width: 420px;
                max-width: 90%;
                padding: 40px;
                text-align: center;
                background: #0f172a;
                border: 1px solid #334155;
                border-radius: 24px;
                box-shadow: 0 25px 80px rgba(0,0,0,.6);
            }}

            img,
            .avatar {{
                width: 100px;
                height: 100px;
                border-radius: 50%;
                margin: auto;
            }}

            img {{
                object-fit: cover;
            }}

            .avatar {{
                background: #334155;
                display: flex;
                justify-content: center;
                align-items: center;
                font-size: 45px;
            }}

            .provider {{
                color: #60a5fa;
                font-weight: bold;
            }}

            .email {{
                color: #cbd5e1;
            }}

            a {{
                display: inline-block;
                margin-top: 20px;
                padding: 12px 25px;
                background: #2563eb;
                color: white;
                text-decoration: none;
                border-radius: 10px;
            }}

        </style>

    </head>

    <body>

        <div class="box">

            {image_html}

            <h1>
                Welcome, {user.get("name", "User")}!
            </h1>

            <p class="provider">
                Logged in with {user.get("provider")}
            </p>

            <p class="email">
                {user.get("email") or "Email not provided"}
            </p>

            <a href="/logout">
                Logout
            </a>

        </div>

    </body>

    </html>
    """


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")


# Run the database availability/table check during normal server startup.
# This does not contain or print any database password.
ensure_users_table()

# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=False
    )