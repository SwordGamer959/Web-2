from flask import Flask, redirect, session, send_from_directory, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from email.message import EmailMessage
import smtplib
import requests
import os
from datetime import datetime, timezone

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=False
    )