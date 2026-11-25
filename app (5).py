import os



import os



os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"



import base64

import json



from google_auth_oauthlib.flow import Flow

import re

import uuid

import hashlib

import secrets

import base64

import hmac

import json



from datetime import datetime, timedelta

from functools import wraps

from email.message import EmailMessage

from urllib.parse import quote



import mysql.connector

from mysql.connector import Error



from dotenv import load_dotenv

from google.oauth2.credentials import Credentials

from google_auth_oauthlib.flow import Flow

from google.auth.transport.requests import Request as GoogleRequest

from googleapiclient.discovery import build

from flask import (

    Flask, render_template, request, jsonify,

    session, redirect, url_for, send_from_directory,

    abort

)

from werkzeug.security import generate_password_hash, check_password_hash

from werkzeug.utils import secure_filename



# ==================================================

# SKILL SWAP - COMPLETE FLASK BACKEND

# MySQL 8.0 + Gmail API OAuth 2.0 + Password Reset

# ==================================================



BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))



app = Flask(__name__)



app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:

    raise RuntimeError(

        "FLASK_SECRET_KEY is missing. Add it to your .env file."

    )



app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024



# --------------------------------------------------

# UPLOAD FOLDERS

# --------------------------------------------------



UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")

PROFILE_DIR = os.path.join(UPLOAD_DIR, "profiles")

DOCUMENT_DIR = os.path.join(UPLOAD_DIR, "documents")

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")



os.makedirs(PROFILE_DIR, exist_ok=True)

os.makedirs(DOCUMENT_DIR, exist_ok=True)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)



# --------------------------------------------------

# MYSQL DATABASE CONFIGURATION

# --------------------------------------------------



DB_CONFIG = {

    "host": os.getenv("DB_HOST", "localhost"),

    "user": os.getenv("DB_USER", "root"),

    "password": os.getenv("DB_PASSWORD", ""),

    "database": os.getenv("DB_NAME", "skill_swap"),

    "port": int(os.getenv("DB_PORT", "3306"))

}





def get_db():

    return mysql.connector.connect(**DB_CONFIG)





def query_db(sql, params=(), fetchone=False, commit=False):

    conn = get_db()

    cursor = conn.cursor(dictionary=True)



    try:

        cursor.execute(sql, params)

        result = None



        if cursor.with_rows:

            result = cursor.fetchone() if fetchone else cursor.fetchall()



        if commit:

            conn.commit()



        return result



    except Exception:

        if commit:

            conn.rollback()

        raise



    finally:

        cursor.close()

        conn.close()





# --------------------------------------------------

# COMMON HELPERS

# --------------------------------------------------



def json_error(message, code=400):

    return jsonify({"message": message}), code





def get_json_data():

    return request.get_json(silent=True) or {}





def current_user_id():

    return session.get("user_id")





def login_required_api(fn):

    @wraps(fn)

    def wrapper(*args, **kwargs):

        if not current_user_id():

            return json_error("Please login first.", 401)

        return fn(*args, **kwargs)

    return wrapper





def login_required_page(fn):

    @wraps(fn)

    def wrapper(*args, **kwargs):

        if not current_user_id():

            return redirect(url_for("login_page"))

        return fn(*args, **kwargs)

    return wrapper





def get_current_user():

    return query_db(

        """

        SELECT id, name, email, mobile, college,

               department, year_of_study, bio, photo,

               teach_skill, learn_skill

        FROM users

        WHERE id=%s

        """,

        (current_user_id(),),

        fetchone=True

    )





def split_skills(value):

    return [

        item.strip()

        for item in (value or "").split(",")

        if item.strip()

    ]





def allowed_pdf(filename):

    return (

        "." in filename

        and filename.rsplit(".", 1)[1].lower() == "pdf"

    )





# --------------------------------------------------

# GMAIL API OAUTH 2.0 CONFIGURATION

# --------------------------------------------------



GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

GOOGLE_CREDENTIALS_FILE = os.path.join(BASE_DIR, "credentials.json")

GOOGLE_TOKEN_FILE = os.path.join(BASE_DIR, "token.json")
GOOGLE_OAUTH_STATE_FILE = os.path.join(BASE_DIR, ".gmail_oauth_state.json")

OAUTH_REDIRECT_URI = os.getenv(

    "OAUTH_REDIRECT_URI",

    "http://127.0.0.1:5000/oauth2callback"

)





def get_gmail_credentials():

    """Load saved Gmail OAuth credentials and refresh them when possible."""

    if not os.path.exists(GOOGLE_TOKEN_FILE):

        return None



    credentials = Credentials.from_authorized_user_file(

        GOOGLE_TOKEN_FILE, GMAIL_SCOPES

    )



    if credentials.expired and credentials.refresh_token:

        credentials.refresh(GoogleRequest())

        with open(GOOGLE_TOKEN_FILE, "w", encoding="utf-8") as token_file:

            token_file.write(credentials.to_json())



    if not credentials.valid:

        return None



    return credentials





def send_reset_email(receiver_email, reset_link):

    """Send a password-reset email through the connected Gmail account."""

    credentials = get_gmail_credentials()

    if not credentials:

        raise RuntimeError(

            "Gmail is not connected. The app owner must visit /connect-gmail first."

        )



    sender_email = os.getenv("GMAIL_SENDER_EMAIL", "").strip()

    if not sender_email:

        raise RuntimeError("GMAIL_SENDER_EMAIL is missing from .env")



    message = EmailMessage()

    message["To"] = receiver_email

    message["From"] = sender_email

    message["Subject"] = "Skill Swap - Reset Your Password"

    message.set_content(f"""Hello,



We received a request to reset your Skill Swap account password.



Use this link to create a new password:



{reset_link}



This link expires in 20 minutes and can be used only once.



If you did not request this reset, you can ignore this email.



Regards,

Skill Swap Team

""")



    encoded_message = base64.urlsafe_b64encode(

        message.as_bytes()

    ).decode("utf-8")



    gmail_service = build(

        "gmail", "v1", credentials=credentials, cache_discovery=False

    )

    gmail_service.users().messages().send(

        userId="me",

        body={"raw": encoded_message}

    ).execute()





# --------------------------------------------------

# OWNER-ONLY GMAIL OAUTH CONNECTION

# --------------------------------------------------



@app.get("/connect-gmail")
def connect_gmail():
    """Start Gmail OAuth for the application owner."""
    supplied_key = request.args.get("key", "")
    expected_key = os.getenv("GMAIL_CONNECT_KEY", "")

    if not expected_key or not hmac.compare_digest(supplied_key, expected_key):
        return json_error("Gmail connection is restricted to the app owner.", 403)

    if not os.path.isfile(GOOGLE_CREDENTIALS_FILE):
        return json_error(
            "credentials.json is missing. Put the Google OAuth Web client JSON beside app.py.",
            500
        )

    try:
        # Validate the OAuth client file before redirecting to Google.
        with open(GOOGLE_CREDENTIALS_FILE, "r", encoding="utf-8") as credential_file:
            client_data = json.load(credential_file)
        if "web" not in client_data:
            return json_error(
                "credentials.json must be downloaded as an OAuth Client ID of type Web application.",
                500
            )

        flow = Flow.from_client_secrets_file(
            GOOGLE_CREDENTIALS_FILE,
            scopes=GMAIL_SCOPES,
            redirect_uri=OAUTH_REDIRECT_URI
        )
        # Generate and preserve the PKCE verifier for the complete OAuth round trip.
        # Google receives only the derived challenge; the verifier must be supplied
        # again when exchanging the authorization code in /oauth2callback.
        code_verifier = secrets.token_urlsafe(64)
        flow.code_verifier = code_verifier

        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )

        # Persist BOTH state and PKCE verifier; the callback creates a new Flow object.
        state_path = GOOGLE_OAUTH_STATE_FILE
        temporary_path = state_path + ".tmp"
        with open(temporary_path, "w", encoding="utf-8") as state_file:
            json.dump({"state": state, "code_verifier": code_verifier}, state_file)
        os.replace(temporary_path, state_path)

        return redirect(authorization_url)

    except Exception as error:
        app.logger.exception("Could not start Gmail OAuth")
        return jsonify({
            "message": "Could not start Gmail authorization.",
            "error_type": type(error).__name__,
            "error_details": str(error)[:500]
        }), 500


@app.get("/oauth2callback")
def oauth2callback():
    """Handle Google's OAuth callback and save Gmail API credentials."""
    returned_state = request.args.get("state", "")
    expected_state = None
    state_data = {}

    try:
        with open(GOOGLE_OAUTH_STATE_FILE, "r", encoding="utf-8") as state_file:
            state_data = json.load(state_file)
        expected_state = state_data.get("state")
    except (OSError, ValueError, TypeError):
        expected_state = None
    finally:
        try:
            os.remove(GOOGLE_OAUTH_STATE_FILE)
        except FileNotFoundError:
            pass

    if request.args.get("error"):
        app.logger.error("Google OAuth returned error: %s", request.args.get("error"))
        return json_error(
            "Google authorization was cancelled or denied. Start Gmail connection again.",
            400
        )

    if (
        not expected_state
        or not returned_state
        or not hmac.compare_digest(str(expected_state), str(returned_state))
    ):
        return json_error(
            "OAuth state is missing or invalid. Start again using the same running Skill Swap server.",
            400
        )

    if not os.path.isfile(GOOGLE_CREDENTIALS_FILE):
        return json_error("credentials.json is missing beside app.py.", 500)

    try:
        flow = Flow.from_client_secrets_file(
            GOOGLE_CREDENTIALS_FILE,
            scopes=GMAIL_SCOPES,
            state=expected_state,
            redirect_uri=OAUTH_REDIRECT_URI
        )

        # Restore the exact verifier used to create the authorization request.
        # Without this, OAuthlib rejects the code exchange with
        # "(invalid_grant) Missing code verifier".
        code_verifier = state_data.get("code_verifier")
        if not code_verifier:
            raise RuntimeError(
                "The saved PKCE code verifier is missing. Restart Gmail connection from /connect-gmail."
            )
        flow.code_verifier = code_verifier

        # The redirect URI in Google Cloud Console must exactly match .env.
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        if not credentials or not credentials.valid:
            raise RuntimeError("Google returned credentials that are not valid.")

        if not credentials.refresh_token:
            raise RuntimeError(
                "Google did not return a refresh token. Revoke this app's access in your Google Account "
                "and connect again; the OAuth request already asks for offline access and consent."
            )

        temporary_token_path = GOOGLE_TOKEN_FILE + ".tmp"
        with open(temporary_token_path, "w", encoding="utf-8") as token_file:
            token_file.write(credentials.to_json())
        os.replace(temporary_token_path, GOOGLE_TOKEN_FILE)

        return (
            "Gmail connected successfully. You can now close this page "
            "and use Forgot Password in Skill Swap."
        )

    except Exception as error:
        app.logger.exception("Gmail OAuth callback failed")
        return jsonify({
            "message": "Gmail authorization failed.",
            "error_type": type(error).__name__,
            "error_details": str(error)[:500],
            "redirect_uri_configured": OAUTH_REDIRECT_URI
        }), 500


# --------------------------------------------------

# HTML PAGE ROUTES

# --------------------------------------------------



@app.get("/")

def home():

    return render_template("index.html")





@app.get("/login")

def login_page():

    return render_template("login.html")





@app.get("/register")

def register_page():

    return render_template("registration.html")





@app.get("/forgot")

def forgot_page():

    return render_template("forgot.html")





@app.get("/reset-password")

def reset_password_page():

    return render_template("reset.html")





@app.get("/dashboard")

@login_required_page

def dashboard_page():

    return render_template("dashboard.html")





@app.get("/profile")

@login_required_page

def profile_page():

    return render_template("profile.html")





@app.get("/myskills")

@login_required_page

def myskills_page():

    return render_template("myskills.html")





@app.get("/findskills")

@login_required_page

def findskills_page():

    return render_template("findskills.html")





@app.get("/skillmatches")

@login_required_page

def matches_page():

    return render_template("skillmatches.html")





@app.get("/sessions")

@login_required_page

def sessions_page():

    return render_template("my_sessions.html")





@app.get("/messages")

@login_required_page

def messages_page():

    return render_template("messages.html")





@app.get("/settings")

@login_required_page

def settings_page():

    return render_template("setting.html")





@app.get("/documents")

@login_required_page

def documents_page():

    return redirect(url_for("dashboard_page") + "#pdfSection")





# --------------------------------------------------

# REGISTRATION API

# --------------------------------------------------



@app.post("/api/register")

def api_register():

    data = get_json_data()



    name = str(data.get("name", "")).strip()

    email = str(data.get("email", "")).strip().lower()

    mobile = str(data.get("mobile", "")).strip()

    password = str(data.get("password", ""))

    college = str(data.get("college", "")).strip()

    teach_skill = str(data.get("teach_skill", "")).strip()

    learn_skill = str(data.get("learn_skill", "")).strip()



    if not all([

        name, email, mobile, password,

        college, teach_skill, learn_skill

    ]):

        return json_error("Please complete all required fields.")



    if not re.fullmatch(r"[0-9]{10}", mobile):

        return json_error("Mobile number must contain exactly 10 digits.")



    if len(password) < 8:

        return json_error("Password must contain at least 8 characters.")



    if teach_skill.casefold() == learn_skill.casefold():

        return json_error("Choose different teaching and learning skills.")



    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):

        return json_error("Enter a valid email address.")



    try:

        query_db(

            """

            INSERT INTO users

                (name, email, mobile, password_hash, college,

                 teach_skill, learn_skill)

            VALUES (%s, %s, %s, %s, %s, %s, %s)

            """,

            (

                name, email, mobile,

                generate_password_hash(password),

                college, teach_skill, learn_skill

            ),

            commit=True

        )



        return jsonify({

            "success": True,

            "message": "Registration successful. Please login."

        }), 201



    except Error as error:

        if error.errno == 1062:

            return json_error(

                "This email or mobile number is already registered.", 409

            )



        app.logger.exception("Registration error")

        return json_error("Database registration error.", 500)





# --------------------------------------------------

# LOGIN API

# --------------------------------------------------



@app.post("/api/login")

def api_login():

    data = request.get_json(silent=True) or request.form



    email = str(data.get("email", "")).strip().lower()

    password = str(data.get("password", ""))



    if not email or not password:

        return json_error("Email and password required.")



    try:

        user = query_db(

            """

            SELECT id, name, email, password_hash, is_active

            FROM users

            WHERE email=%s

            """,

            (email,),

            fetchone=True

        )



        if not user:

            return json_error("Invalid email or password.", 401)



        if not user["is_active"]:

            return json_error("Your account is inactive.", 403)



        if not check_password_hash(user["password_hash"], password):

            return json_error("Invalid email or password.", 401)



        session.clear()

        session["user_id"] = user["id"]

        session["user_name"] = user["name"]



        return jsonify({

            "message": "Login successful",

            "redirect": "/dashboard"

        }), 200



    except Exception:

        app.logger.exception("Login error")

        return json_error("Login failed. Check server error.", 500)





# --------------------------------------------------

# LOGOUT API

# --------------------------------------------------



@app.post("/api/logout")

def api_logout():

    session.clear()

    return jsonify({"message": "Logged out successfully."})





@app.get("/logout")

def logout_page():

    session.clear()

    return redirect(url_for("home"))





# --------------------------------------------------

# CURRENT USER API

# --------------------------------------------------



@app.get("/api/me")

@login_required_api

def api_me():

    user = get_current_user()



    if not user:

        return json_error("User not found.", 404)



    if user.get("photo"):

        # Photo is stored as a static URL path.

        if user["photo"].startswith("/static/"):

            pass

        else:

            user["photo"] = url_for(

                "profile_photo", filename=user["photo"]

            )



    return jsonify(user)





# --------------------------------------------------

# PROFILE API

# --------------------------------------------------



@app.route("/api/profile", methods=["GET", "POST"])

@login_required_api

def profile_api():

    user_id = current_user_id()



    if request.method == "GET":

        user = query_db(

            """

            SELECT name, email, mobile AS phone, college,

                   department, year_of_study, bio,

                   teach_skill, learn_skill, photo

            FROM users

            WHERE id=%s

            """,

            (user_id,),

            fetchone=True

        )



        if not user:

            return json_error("User not found.", 404)



        return jsonify({

            "name": user.get("name") or "",

            "email": user.get("email") or "",

            "phone": user.get("mobile") or "",
            
            "college": user.get("college") or "",

            "department": user.get("department") or "",

            "year_of_study": user.get("year_of_study") or "",

            "bio": user.get("bio") or "",

            "teach_skill": user.get("teach_skill") or "",

            "learn_skill": user.get("learn_skill") or "",

            "photo": user.get("photo") or ""

        })



    data = get_json_data()

    if not data:

        return json_error("Invalid JSON data.")



    name = str(data.get("name", "")).strip()

    mobile = str(data.get("mobile", "")).strip()

    college = str(data.get("college", "")).strip()

    department = str(data.get("department", "")).strip()

    year = str(data.get("year_of_study", "")).strip()

    bio = str(data.get("bio", "")).strip()

    teach_skill = str(data.get("teach_skill", "")).strip()

    learn_skill = str(data.get("learn_skill", "")).strip()



    if not name or not mobile:

        return json_error("Name and phone number are required.")



    if not mobile.isdigit() or len(mobile) != 10:

        return json_error("Enter a valid 10-digit mobile number.")



    try:

        query_db(

            """

            UPDATE users

            SET name=%s, mobile=%s, college=%s,

                department=%s, year_of_study=%s, bio=%s,

                teach_skill=%s, learn_skill=%s

            WHERE id=%s

            """,

            (

                name, mobile, college, department, year,

                bio, teach_skill, learn_skill, user_id

            ),

            commit=True

        )



        session["user_name"] = name

        return jsonify({

            "success": True,

            "message": "Profile updated successfully!"

        })



    except Error as error:

        if error.errno == 1062:

            return json_error("This mobile number is already registered.", 409)

        app.logger.exception("Profile update error")

        return json_error("Profile update failed. Check database.", 500)





# --------------------------------------------------

# PROFILE PHOTO UPLOAD

# --------------------------------------------------



@app.post("/api/profile/photo")

@login_required_api

def upload_profile_photo():

    user_id = current_user_id()



    if "photo" not in request.files:

        return json_error("Please select a photo.")



    file = request.files["photo"]

    if not file.filename:

        return json_error("No file selected.")



    filename = secure_filename(file.filename)

    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if extension not in {"jpg", "jpeg", "png", "webp"}:

        return json_error("Only JPG, PNG and WEBP allowed.")



    file.seek(0, os.SEEK_END)

    size = file.tell()

    file.seek(0)



    if size > 5 * 1024 * 1024:

        return json_error("Image must be smaller than 5 MB.")



    try:

        new_filename = f"{uuid.uuid4().hex}.{extension}"

        file.save(os.path.join(UPLOAD_FOLDER, new_filename))

        photo_path = f"/static/uploads/{new_filename}"



        query_db(

            "UPDATE users SET photo=%s WHERE id=%s",

            (photo_path, user_id),

            commit=True

        )



        return jsonify({

            "success": True,

            "message": "Profile picture uploaded successfully.",

            "photo": photo_path

        })



    except Exception:

        app.logger.exception("Photo upload error")

        return json_error("Photo upload failed.", 500)





# --------------------------------------------------

# MY SKILLS API

# --------------------------------------------------



@app.route("/api/skills", methods=["GET", "POST"])

@login_required_api

def api_skills():

    uid = current_user_id()



    if request.method == "GET":

        row = query_db(

            "SELECT teach_skill, learn_skill FROM users WHERE id=%s",

            (uid,),

            fetchone=True

        )

        return jsonify(row or {"teach_skill": "", "learn_skill": ""})



    data = get_json_data()

    teach = str(data.get("teach_skill", "")).strip()

    learn = str(data.get("learn_skill", "")).strip()



    if teach.casefold() == learn.casefold() and teach:

        return json_error("Teaching and learning skills must be different.")



    query_db(

        """

        UPDATE users

        SET teach_skill=%s, learn_skill=%s

        WHERE id=%s

        """,

        (teach, learn, uid),

        commit=True

    )

    return jsonify({"message": "Skills saved successfully."})





# --------------------------------------------------

# FIND SKILLS API

# --------------------------------------------------



@app.get("/api/find-skills")

@login_required_api

def api_find_skills():

    skill = str(request.args.get("skill", "")).strip()

    uid = current_user_id()

    like = "%" + skill + "%"



    rows = query_db(

        """

        SELECT id, name, email, college, teach_skill, learn_skill

        FROM users

        WHERE id <> %s

          AND is_active=1

          AND (

              %s = ''

              OR teach_skill LIKE %s

              OR learn_skill LIKE %s

          )

        ORDER BY name

        """,

        (uid, skill, like, like)

    )

    return jsonify(rows)





# --------------------------------------------------

# SKILL MATCHES API

# --------------------------------------------------



@app.get("/api/skill-matches")

@login_required_api

def api_skill_matches():

    uid = current_user_id()



    me = query_db(

        "SELECT teach_skill, learn_skill FROM users WHERE id=%s",

        (uid,),

        fetchone=True

    )

    if not me:

        return jsonify([])



    my_teach = split_skills(me["teach_skill"])

    my_learn = split_skills(me["learn_skill"])



    users = query_db(

        """

        SELECT id, name, email, college, teach_skill, learn_skill

        FROM users

        WHERE id <> %s AND is_active=1

        """,

        (uid,)

    )



    matches = []

    for user in users:

        their_teach = split_skills(user["teach_skill"])

        their_learn = split_skills(user["learn_skill"])



        can_teach = [

            skill for skill in their_teach

            if any(skill.casefold() == wanted.casefold() for wanted in my_learn)

        ]

        want_to_learn = [

            skill for skill in their_learn

            if any(skill.casefold() == offered.casefold() for offered in my_teach)

        ]



        if can_teach or want_to_learn:

            matches.append({

                "id": user["id"],

                "name": user["name"],

                "email": user["email"],

                "college": user["college"],

                "they_can_teach": can_teach,

                "they_want_to_learn": want_to_learn

            })



    return jsonify(matches)





# --------------------------------------------------

# MESSAGES API

# --------------------------------------------------



@app.route("/api/messages", methods=["GET", "POST"])

@login_required_api

def api_messages():

    uid = current_user_id()



    if request.method == "GET":

        partner_email = str(request.args.get("email", "")).strip().lower()

        if not partner_email:

            return json_error("Enter a student email.")



        partner = query_db(

            "SELECT id FROM users WHERE email=%s",

            (partner_email,),

            fetchone=True

        )

        if not partner:

            return json_error("Student email not found.", 404)



        rows = query_db(

            """

            SELECT m.id, m.sender_id, m.receiver_id, m.message,

                   m.created_at, u.name AS sender_name

            FROM messages m

            JOIN users u ON u.id=m.sender_id

            WHERE (m.sender_id=%s AND m.receiver_id=%s)

               OR (m.sender_id=%s AND m.receiver_id=%s)

            ORDER BY m.created_at

            """,

            (uid, partner["id"], partner["id"], uid)

        )



        for row in rows:

            row["is_mine"] = row["sender_id"] == uid

        return jsonify(rows)



    data = get_json_data()

    email = str(data.get("email", "")).strip().lower()

    message = str(data.get("message", "")).strip()



    partner = query_db(

        "SELECT id FROM users WHERE email=%s",

        (email,),

        fetchone=True

    )

    if not partner:

        return json_error("Student email not found.", 404)

    if partner["id"] == uid:

        return json_error("You cannot message yourself.")

    if not message or len(message) > 2000:

        return json_error("Message must contain 1 to 2000 characters.")



    query_db(

        """

        INSERT INTO messages(sender_id, receiver_id, message)

        VALUES(%s, %s, %s)

        """,

        (uid, partner["id"], message),

        commit=True

    )

    return jsonify({"message": "Message sent successfully."}), 201





# --------------------------------------------------

# SESSION API

# --------------------------------------------------



@app.route("/api/sessions", methods=["GET", "POST", "PATCH"])

@login_required_api

def api_sessions():

    uid = current_user_id()



    if request.method == "GET":

        rows = query_db(

            """

            SELECT s.id, s.requester_id, s.partner_id, s.skill,

                   s.session_date, s.meeting_mode, s.notes, s.status,

                   u.name AS other_student, u.email AS other_email,

                   %s AS current_user_id

            FROM sessions s

            JOIN users u

              ON u.id=IF(s.requester_id=%s, s.partner_id, s.requester_id)

            WHERE s.requester_id=%s OR s.partner_id=%s

            ORDER BY s.session_date DESC

            """,

            (uid, uid, uid, uid)

        )

        return jsonify(rows)



    data = get_json_data()



    if request.method == "POST":

        email = str(data.get("email", "")).strip().lower()

        skill = str(data.get("skill", "")).strip()

        date_text = str(data.get("session_date", "")).strip()

        mode = str(data.get("meeting_mode", "Online")).strip()

        notes = str(data.get("notes", "")).strip()



        if not email or not skill or not date_text:

            return json_error("Complete all required session fields.")

        if mode not in {"Online", "Offline"}:

            return json_error("Invalid meeting mode.")



        partner = query_db(

            "SELECT id FROM users WHERE email=%s AND is_active=1",

            (email,),

            fetchone=True

        )

        if not partner:

            return json_error("Partner email not found.", 404)

        if partner["id"] == uid:

            return json_error("You cannot schedule a session with yourself.")



        try:

            session_date = datetime.fromisoformat(date_text)

        except ValueError:

            return json_error("Please provide a valid session date.")



        if session_date <= datetime.now():

            return json_error("Choose a future date and time.")



        query_db(

            """

            INSERT INTO sessions

                (requester_id, partner_id, skill, session_date, meeting_mode, notes)

            VALUES (%s, %s, %s, %s, %s, %s)

            """,

            (uid, partner["id"], skill, session_date, mode, notes),

            commit=True

        )

        return jsonify({"message": "Session request sent."}), 201



    session_id = data.get("session_id")

    new_status = str(data.get("status", "")).strip()



    if new_status not in {"Accepted", "Rejected", "Cancelled", "Completed"}:

        return json_error("Invalid session status.")



    row = query_db(

        "SELECT requester_id, partner_id, status FROM sessions WHERE id=%s",

        (session_id,),

        fetchone=True

    )

    if not row:

        return json_error("Session not found.", 404)

    if uid not in (row["requester_id"], row["partner_id"]):

        return json_error("You cannot update this session.", 403)



    if row["status"] != "Pending":

        if not (new_status == "Completed" and row["status"] == "Accepted"):

            return json_error("This session can no longer be changed.")



    if new_status in {"Accepted", "Rejected"} and uid != row["partner_id"]:

        return json_error("Only the invited partner can accept or reject.")

    if new_status == "Cancelled" and uid != row["requester_id"]:

        return json_error("Only the requester can cancel this session.")

    if new_status == "Completed" and uid not in (

        row["requester_id"], row["partner_id"]

    ):

        return json_error("You cannot complete this session.", 403)



    query_db(

        "UPDATE sessions SET status=%s WHERE id=%s",

        (new_status, session_id),

        commit=True

    )

    return jsonify({"message": "Session updated successfully."})





# --------------------------------------------------

# PDF DOCUMENT API

# --------------------------------------------------



@app.route("/api/documents", methods=["GET", "POST", "DELETE"])

@login_required_api

def api_documents():

    uid = current_user_id()



    if request.method == "GET":

        rows = query_db(

            """

            SELECT id, original_name, created_at

            FROM documents

            WHERE user_id=%s

            ORDER BY id DESC

            """,

            (uid,)

        )

        return jsonify(rows)



    if request.method == "POST":

        file = request.files.get("pdf")

        if not file or not file.filename:

            return json_error("Please select a PDF file.")

        if not allowed_pdf(file.filename):

            return json_error("Only PDF files are allowed.")



        header = file.stream.read(5)

        file.stream.seek(0)

        if header != b"%PDF-":

            return json_error("The selected file is not a valid PDF.")



        stored_name = uuid.uuid4().hex + ".pdf"

        original_name = secure_filename(file.filename)

        file_path = os.path.join(DOCUMENT_DIR, stored_name)



        try:

            file.save(file_path)

            query_db(

                """

                INSERT INTO documents(user_id, original_name, stored_name)

                VALUES(%s, %s, %s)

                """,

                (uid, original_name, stored_name),

                commit=True

            )

            return jsonify({"message": "PDF uploaded successfully."}), 201

        except Exception:

            if os.path.exists(file_path):

                os.remove(file_path)

            app.logger.exception("Document upload error")

            return json_error("PDF upload failed.", 500)



    document_id = request.args.get("id")

    row = query_db(

        "SELECT stored_name FROM documents WHERE id=%s AND user_id=%s",

        (document_id, uid),

        fetchone=True

    )

    if not row:

        return json_error("Document not found.", 404)



    file_path = os.path.join(DOCUMENT_DIR, row["stored_name"])

    query_db(

        "DELETE FROM documents WHERE id=%s AND user_id=%s",

        (document_id, uid),

        commit=True

    )

    if os.path.exists(file_path):

        os.remove(file_path)



    return jsonify({"message": "PDF deleted successfully."})





@app.patch("/api/documents/<int:document_id>")

@login_required_api

def rename_document(document_id):

    data = get_json_data()

    new_name = str(data.get("original_name", "")).strip()



    if not new_name:

        return json_error("Enter a new document name.")

    if len(new_name) > 255:

        return json_error("Document name is too long.")

    if not new_name.lower().endswith(".pdf"):

        new_name += ".pdf"



    row = query_db(

        "SELECT id FROM documents WHERE id=%s AND user_id=%s",

        (document_id, current_user_id()),

        fetchone=True

    )

    if not row:

        return json_error("Document not found.", 404)



    query_db(

        """

        UPDATE documents SET original_name=%s

        WHERE id=%s AND user_id=%s

        """,

        (secure_filename(new_name), document_id, current_user_id()),

        commit=True

    )

    return jsonify({"message": "PDF renamed successfully."})





@app.get("/api/documents/<int:document_id>/<action>")

@login_required_api

def document_file(document_id, action):

    if action not in {"view", "download"}:

        abort(404)



    row = query_db(

        """

        SELECT stored_name, original_name

        FROM documents

        WHERE id=%s AND user_id=%s

        """,

        (document_id, current_user_id()),

        fetchone=True

    )

    if not row:

        return json_error("Document not found.", 404)



    return send_from_directory(

        DOCUMENT_DIR,

        row["stored_name"],

        as_attachment=(action == "download"),

        download_name=row["original_name"],

        mimetype="application/pdf"

    )





# --------------------------------------------------

# CHANGE PASSWORD API (LOGGED-IN USER)

# --------------------------------------------------



@app.post("/api/change-password")

@login_required_api

def change_password():

    data = get_json_data()

    current_password = str(data.get("current_password", ""))

    new_password = str(data.get("new_password", ""))



    if len(new_password) < 8:

        return json_error("New password must contain at least 8 characters.")



    row = query_db(

        "SELECT password_hash FROM users WHERE id=%s",

        (current_user_id(),),

        fetchone=True

    )

    if not row or not check_password_hash(row["password_hash"], current_password):

        return json_error("Current password is incorrect.", 401)



    query_db(

        "UPDATE users SET password_hash=%s WHERE id=%s",

        (generate_password_hash(new_password), current_user_id()),

        commit=True

    )



    # Invalidate outstanding password-reset links after password change.

    query_db(

        """

        UPDATE password_reset_tokens SET used=1

        WHERE user_id=%s AND used=0

        """,

        (current_user_id(),),

        commit=True

    )



    return jsonify({"message": "Password changed successfully."})





# --------------------------------------------------

# FORGOT PASSWORD API - SEND GMAIL RESET LINK

# --------------------------------------------------



@app.post("/api/forgot-password")

def forgot_password():

    data = get_json_data()

    email = str(data.get("email", "")).strip().lower()



    if not email:

        return json_error("Enter your registered email.")



    generic_message = (

        "If this email is registered, password reset instructions "

        "will be sent to your email."

    )



    token_hash = None



    try:

        user = query_db(

            "SELECT id, email FROM users WHERE email=%s",

            (email,),

            fetchone=True

        )



        if not user:

            # This explicit response was requested for the student project.

            # For a public production service, use the generic response instead

            # to avoid revealing which email addresses have accounts.

            return jsonify({"message": "Invalid email. This email is not registered."}), 404



        # Invalidate older unused tokens for this account.

        query_db(

            """

            UPDATE password_reset_tokens SET used=1

            WHERE user_id=%s AND used=0

            """,

            (user["id"],),

            commit=True

        )



        token = secrets.token_urlsafe(32)

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

        expires_at = datetime.now() + timedelta(minutes=20)



        query_db(

            """

            INSERT INTO password_reset_tokens

                (user_id, token_hash, expires_at, used)

            VALUES (%s, %s, %s, 0)

            """,

            (user["id"], token_hash, expires_at),

            commit=True

        )



        base_url = os.getenv(

            "APP_BASE_URL", "http://127.0.0.1:5000"

        ).rstrip("/")

        reset_link = (

            f"{base_url}/reset-password?token={quote(token)}"

        )



        send_reset_email(user["email"], reset_link)

        return jsonify({"message": generic_message}), 200



    except Exception:

        app.logger.exception("Forgot password email error")



        if token_hash:

            try:

                query_db(

                    """

                    DELETE FROM password_reset_tokens

                    WHERE token_hash=%s AND used=0

                    """,

                    (token_hash,),

                    commit=True

                )

            except Exception:

                app.logger.exception("Reset token cleanup error")



        # Generic response avoids revealing whether an email is registered.

        return jsonify({"message": generic_message}), 200





# --------------------------------------------------

# RESET PASSWORD API - TOKEN VALIDATION + DB UPDATE

# --------------------------------------------------



@app.post("/api/reset-password")

def api_reset_password():

    data = get_json_data()

    token = str(data.get("token", "")).strip()

    new_password = str(data.get("password", ""))



    if not token:

        return json_error("Invalid or missing reset token.")

    if len(new_password) < 8:

        return json_error("Password must contain at least 8 characters.")



    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()



    conn = None

    cursor = None



    try:

        conn = get_db()

        conn.start_transaction()

        cursor = conn.cursor(dictionary=True)



        cursor.execute(

            """

            SELECT id, user_id

            FROM password_reset_tokens

            WHERE token_hash=%s

              AND used=0

              AND expires_at > NOW()

            FOR UPDATE

            """,

            (token_hash,)

        )

        reset_row = cursor.fetchone()



        if not reset_row:

            conn.rollback()

            return json_error(

                "Reset link is invalid or expired. Please request a new one.",

                400

            )



        cursor.execute(

            """

            UPDATE users

            SET password_hash=%s

            WHERE id=%s

            """,

            (

                generate_password_hash(new_password),

                reset_row["user_id"]

            )

        )



        if cursor.rowcount != 1:

            conn.rollback()

            return json_error("User account not found.", 404)



        cursor.execute(

            """

            UPDATE password_reset_tokens

            SET used=1

            WHERE user_id=%s AND used=0

            """,

            (reset_row["user_id"],)

        )



        conn.commit()



        return jsonify({

            "success": True,

            "message": "Password reset successful. Please login."

        }), 200



    except Exception:

        if conn:

            conn.rollback()

        app.logger.exception("Reset password error")

        return json_error("Password reset failed. Please try again.", 500)



    finally:

        if cursor:

            cursor.close()

        if conn and conn.is_connected():

            conn.close()





# --------------------------------------------------

# HEALTH CHECK

# --------------------------------------------------



@app.get("/health")

def health():

    try:

        row = query_db("SELECT 1 AS ok", fetchone=True)

        return jsonify({

            "status": "ok",

            "database": bool(row and row["ok"] == 1)

        })

    except Error:

        app.logger.exception("Database health check failed")

        return json_error(

            "Database connection failed. Check MySQL configuration.",

            500

        )





# --------------------------------------------------

# ERROR HANDLERS

# --------------------------------------------------



@app.errorhandler(413)

def file_too_large(error):

    return json_error(

        "File is too large. Maximum upload size is 10 MB.",

        413

    )





@app.errorhandler(404)

def page_not_found(error):

    if request.path.startswith("/api/"):

        return json_error("API endpoint not found.", 404)

    return "Page not found.", 404





# --------------------------------------------------

# RUN FLASK APPLICATION

# --------------------------------------------------



if __name__ == "__main__":
    # 0.0.0.0 allows access from this PC and, when firewall/network permit,
    # other devices on the same local network. Set APP_BASE_URL in .env
    # to the PC's LAN IP when opening reset links on another device.
    flask_host = os.getenv("FLASK_HOST", "0.0.0.0")
    flask_port = int(os.getenv("PORT", "5000"))
    app.run(
        host=flask_host,
        port=flask_port,
        debug=os.getenv("FLASK_DEBUG", "true").lower() == "true"
    )
