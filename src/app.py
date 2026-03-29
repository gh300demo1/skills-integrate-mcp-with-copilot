"""
High School Management System API

A super simple FastAPI application that allows students to view and sign up
for extracurricular activities at Mergington High School.
"""

from fastapi import FastAPI, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
import os
from pathlib import Path
import json
import base64
import hashlib
import hmac
import time
import secrets

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

USERS_FILE = current_dir / "users.json"
SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "change-this-secret-in-production")
TOKEN_EXPIRATION_SECONDS = 60 * 60 * 24


def load_users():
    if USERS_FILE.exists():
        with USERS_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_users():
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


def sign_payload(payload: str) -> str:
    return hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_token(user: dict) -> str:
    payload = json.dumps({
        "id": user["id"],
        "role": user["role"],
        "exp": int(time.time()) + TOKEN_EXPIRATION_SECONDS
    })
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("utf-8")
    signature = sign_payload(encoded)
    return f"{encoded}.{signature}"


def decode_token(token: str) -> dict:
    try:
        encoded, signature = token.split(".")
        expected_signature = sign_payload(encoded)
        if not hmac.compare_digest(expected_signature, signature):
            raise ValueError("Invalid token signature")

        padding = "=" * (-len(encoded) % 4)
        decoded = base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
        payload = json.loads(decoded)
        if payload.get("exp", 0) < int(time.time()):
            raise ValueError("Token expired")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization must be Bearer token")

    token = authorization.split(" ", 1)[1]
    payload = decode_token(token)
    user = users.get(payload["id"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def sanitize_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "is_verified": user.get("is_verified", False)
    }


users = load_users()


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


@app.post("/users/register")
def register_user(name: str, email: str, password: str, role: str = "student"):
    if role not in {"student", "admin"}:
        raise HTTPException(status_code=400, detail="Role must be either 'student' or 'admin'")
    if email in users:
        raise HTTPException(status_code=400, detail="Email already registered")

    verification_code = secrets.token_hex(3)
    user = {
        "id": email,
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "is_verified": False,
        "verification_code": verification_code
    }
    users[email] = user
    save_users()

    token = generate_token(user)
    return {
        "message": "Registration successful. Please verify your email.",
        "verification_code": verification_code,
        "access_token": token,
        "token_type": "bearer",
        "user": sanitize_user(user)
    }


@app.post("/users/login")
def login_user(email: str, password: str):
    user = users.get(email)
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.get("is_verified", False):
        raise HTTPException(status_code=403, detail="Email not verified")

    token = generate_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": sanitize_user(user)
    }


@app.get("/users/me")
def get_profile(authorization: str = Header(None)):
    user = get_current_user(authorization)
    return sanitize_user(user)


@app.put("/users/me")
def update_profile(name: str = None, authorization: str = Header(None)):
    user = get_current_user(authorization)
    if name:
        user["name"] = name
        save_users()
    return sanitize_user(user)


@app.put("/users/me/password")
def change_password(current_password: str, new_password: str, authorization: str = Header(None)):
    user = get_current_user(authorization)
    if not verify_password(current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    user["password_hash"] = hash_password(new_password)
    save_users()
    return {"message": "Password updated successfully"}


@app.post("/users/verify-email")
def verify_email(email: str, code: str):
    user = users.get(email)
    if not user or user.get("verification_code") != code:
        raise HTTPException(status_code=400, detail="Invalid email or verification code")
    user["is_verified"] = True
    user.pop("verification_code", None)
    save_users()
    return {"message": "Email verified successfully"}


@app.post("/users/forgot-password")
def forgot_password(email: str):
    user = users.get(email)
    if user:
        reset_code = secrets.token_hex(3)
        user["reset_code"] = reset_code
        save_users()
        return {"message": "Password reset code generated", "reset_code": reset_code}
    return {"message": "If the email exists, a reset code has been generated"}


@app.post("/users/reset-password")
def reset_password(email: str, reset_code: str, new_password: str):
    user = users.get(email)
    if not user or user.get("reset_code") != reset_code:
        raise HTTPException(status_code=400, detail="Invalid email or reset code")
    user["password_hash"] = hash_password(new_password)
    user.pop("reset_code", None)
    save_users()
    return {"message": "Password has been reset successfully"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str = None, authorization: str = Header(None)):
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    current_user = None
    if authorization:
        current_user = get_current_user(authorization)
        if current_user["role"] == "student":
            if email and email != current_user["email"]:
                raise HTTPException(status_code=403, detail="Students can only sign up themselves")
            email = current_user["email"]
        elif current_user["role"] == "admin" and not email:
            email = current_user["email"]

    if not email:
        raise HTTPException(status_code=400, detail="Email is required to sign up")

    activity = activities[activity_name]
    if email in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is already signed up")

    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str = None, authorization: str = Header(None)):
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    current_user = None
    if authorization:
        current_user = get_current_user(authorization)
        if current_user["role"] == "student":
            if email and email != current_user["email"]:
                raise HTTPException(status_code=403, detail="Students can only unregister themselves")
            email = current_user["email"]
        elif current_user["role"] == "admin" and not email:
            email = current_user["email"]

    if not email:
        raise HTTPException(status_code=400, detail="Email is required to unregister")

    activity = activities[activity_name]
    if email not in activity["participants"]:
        raise HTTPException(status_code=400, detail="Student is not signed up for this activity")

    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
