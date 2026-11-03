"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

TEACHERS_FILE = current_dir / "teachers.json"
SESSION_COOKIE = "teacher_session"
SESSION_MAX_AGE = 8 * 60 * 60
PASSWORD_HASH_ITERATIONS = 310_000
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_bytes(32))
if isinstance(SESSION_SECRET, str):
    SESSION_SECRET = SESSION_SECRET.encode("utf-8")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() == "true"


def load_teacher_credentials():
    with TEACHERS_FILE.open(encoding="utf-8") as file:
        data = json.load(file)
    if not isinstance(data, dict) or not isinstance(data.get("teachers"), list):
        raise ValueError("teachers.json must contain a 'teachers' list")
    credentials = {}
    for teacher in data["teachers"]:
        if (
            not isinstance(teacher, dict)
            or not isinstance(teacher.get("username"), str)
            or not teacher["username"]
            or not isinstance(teacher.get("password_hash"), str)
        ):
            raise ValueError("Each teacher needs a username and password_hash")
        if teacher["username"] in credentials:
            raise ValueError(f"Duplicate teacher username: {teacher['username']}")
        credentials[teacher["username"]] = teacher["password_hash"]
    return credentials


teacher_credentials = load_teacher_credentials()


class LoginRequest(BaseModel):
    username: str
    password: str


def verify_password(password, encoded_hash):
    try:
        algorithm, iterations, salt, expected_hash = encoded_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        actual_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        ).hex()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual_hash, expected_hash)


def create_session(username):
    payload = json.dumps(
        {"sub": username, "exp": int(time.time()) + SESSION_MAX_AGE},
        separators=(",", ":"),
    ).encode("utf-8")
    encoded_payload = base64.urlsafe_b64encode(payload).rstrip(b"=")
    signature = hmac.new(SESSION_SECRET, encoded_payload, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return (encoded_payload + b"." + encoded_signature).decode("ascii")


def get_session_username(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None

    try:
        encoded_payload, encoded_signature = token.encode("ascii").split(b".", 1)
        expected_signature = hmac.new(
            SESSION_SECRET, encoded_payload, hashlib.sha256
        ).digest()
        signature = base64.urlsafe_b64decode(
            encoded_signature + b"=" * (-len(encoded_signature) % 4)
        )
        if not hmac.compare_digest(signature, expected_signature):
            return None

        payload = base64.urlsafe_b64decode(
            encoded_payload + b"=" * (-len(encoded_payload) % 4)
        )
        session = json.loads(payload)
        username = session["sub"]
        if session["exp"] <= time.time() or username not in teacher_credentials:
            return None
        return username
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def require_teacher(request: Request):
    username = get_session_username(request)
    if username is None:
        raise HTTPException(status_code=401, detail="Teacher login required")
    return username


@app.post("/auth/login")
def login(credentials: LoginRequest):
    password_hash = teacher_credentials.get(credentials.username)
    if password_hash is None or not verify_password(
        credentials.password, password_hash
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response = JSONResponse({"message": "Logged in successfully"})
    response.set_cookie(
        SESSION_COOKIE,
        create_session(credentials.username),
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return response


@app.get("/auth/status")
def auth_status(request: Request):
    username = get_session_username(request)
    return {"authenticated": username is not None, "username": username}


@app.post("/auth/logout")
def logout():
    response = JSONResponse({"message": "Logged out successfully"})
    response.delete_cookie(
        SESSION_COOKIE, httponly=True, secure=COOKIE_SECURE, samesite="strict",
        path="/"
    )
    return response

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str, _: str = Depends(require_teacher)):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str, email: str, _: str = Depends(require_teacher)
):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
