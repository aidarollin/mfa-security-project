from flask import Flask, render_template, request, redirect, url_for, session
import os
import time
import sqlite3
import random
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from ml_model import predict_risk, ensure_model_ready

app = Flask(__name__)
app.secret_key = "mfa_demo_secret_key_2025"   # Use a real env var in production

DB_PATH        = os.path.join("instance", "auth.db")
BLOCK_THRESHOLD = 5
BLOCK_DURATION  = 60   # seconds

# In-memory state (replace with Redis / DB in production)
login_tracker: dict = {}
otp_store:     dict = {}


# ── Database helpers ──────────────────────────────────────────────────────────

def get_db():
    os.makedirs("instance", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            username      TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            email         TEXT,
            known_devices TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS login_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT,
            timestamp     TEXT,
            ip_address    TEXT,
            device_id     TEXT,
            failed_before INTEGER,
            risk_level    TEXT,
            risk_score    REAL,
            outcome       TEXT
        );
    """)
    demo_users = [
        ("student1", generate_password_hash("Secure123!"),     "student1@example.com", "laptop-01,phone-01"),
        ("student2", generate_password_hash("StrongPass456!"), "student2@example.com", "phone-02"),
        ("admin",    generate_password_hash("Admin@789"),      "admin@example.com",    "workstation-01"),
    ]
    for row in demo_users:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash, email, known_devices) VALUES (?,?,?,?)",
            row,
        )
    conn.commit()
    conn.close()


def get_user(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return user


def log_attempt(username, ip, device_id, failed_before, risk_level, risk_score, outcome):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_logs "
        "(username,timestamp,ip_address,device_id,failed_before,risk_level,risk_score,outcome) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (
            username,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            device_id,
            failed_before,
            risk_level,
            round(risk_score, 4),
            outcome,
        ),
    )
    conn.commit()
    conn.close()


def update_last_log_outcome(username, outcome):
    conn = get_db()
    conn.execute(
        "UPDATE login_logs SET outcome=? "
        "WHERE id=(SELECT MAX(id) FROM login_logs WHERE username=?)",
        (outcome, username),
    )
    conn.commit()
    conn.close()


# ── Login-behaviour helpers ───────────────────────────────────────────────────

def init_tracker(username):
    if username not in login_tracker:
        login_tracker[username] = {
            "failed_attempts":   0,
            "last_attempt_time": 0.0,
            "blocked_until":     0.0,
        }


def is_unusual_hour() -> int:
    h = datetime.now().hour
    return 1 if (h < 6 or h >= 23) else 0


def extract_features(username: str, device_id: str, password_correct: bool) -> dict:
    init_tracker(username)
    t   = login_tracker[username]
    now = time.time()

    short_interval = 1 if (now - t["last_attempt_time"]) < 5 else 0

    user           = get_user(username)
    unknown_device = 1
    if user and device_id in user["known_devices"].split(","):
        unknown_device = 0

    features = {
        "failed_attempts": min(t["failed_attempts"], 10),
        "short_interval":  short_interval,
        "unknown_device":  unknown_device,
        "unusual_hour":    is_unusual_hour(),
        "password_match":  1 if password_correct else 0,
    }
    t["last_attempt_time"] = now
    return features


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username  = request.form.get("username", "").strip()
        password  = request.form.get("password", "")
        device_id = request.form.get("device_id", "").strip()
        ip        = request.remote_addr

        init_tracker(username)
        tracker = login_tracker[username]

        # ── Block check ───────────────────────────────────────────────────────
        if time.time() < tracker["blocked_until"]:
            remaining = int(tracker["blocked_until"] - time.time())
            return render_template("blocked.html", remaining=remaining, reason="failed_attempts")

        # ── Password verification ─────────────────────────────────────────────
        user  = get_user(username)
        pw_ok = bool(user and check_password_hash(user["password_hash"], password))

        features                   = extract_features(username, device_id, pw_ok)
        risk_level, risk_score     = predict_risk(features)

        # ── Wrong password ────────────────────────────────────────────────────
        if not pw_ok:
            tracker["failed_attempts"] += 1
            if tracker["failed_attempts"] >= BLOCK_THRESHOLD:
                tracker["blocked_until"] = time.time() + BLOCK_DURATION
                log_attempt(username, ip, device_id, tracker["failed_attempts"],
                            "high", risk_score, "blocked")
                return render_template("blocked.html", remaining=BLOCK_DURATION,
                                       reason="failed_attempts")

            log_attempt(username, ip, device_id, tracker["failed_attempts"],
                        risk_level, risk_score, "denied")
            return render_template(
                "login.html",
                error=f"Invalid credentials — attempt {tracker['failed_attempts']}/{BLOCK_THRESHOLD}",
                risk_level=risk_level,
                attempts=tracker["failed_attempts"],
                threshold=BLOCK_THRESHOLD,
            )

        # ── Correct password ──────────────────────────────────────────────────
        tracker["failed_attempts"] = 0

        # High risk even on correct password → could be attacker who finally guessed right
        if risk_level == "high":
            tracker["blocked_until"] = time.time() + BLOCK_DURATION
            log_attempt(username, ip, device_id, features["failed_attempts"],
                        risk_level, risk_score, "blocked_high_risk")
            return render_template("blocked.html", remaining=BLOCK_DURATION,
                                   reason="high_risk")

        # Generate 6-digit OTP (all successful password checks require MFA)
        otp = str(random.randint(100000, 999999))
        otp_store[username] = {"otp": otp, "expires": time.time() + 300}

        session["pending_username"] = username
        session["risk_level"]       = risk_level
        session["risk_score"]       = risk_score

        log_attempt(username, ip, device_id, features["failed_attempts"],
                    risk_level, risk_score, "otp_sent")

        print(f"\n{'='*44}")
        print(f"  DEMO OTP for [{username}] :  {otp}")
        print(f"{'='*44}\n")

        if risk_level == "medium":
            time.sleep(2)   # artificial delay for suspicious-but-not-blocked logins

        return redirect(url_for("otp_verification"))

    return render_template("login.html")


@app.route("/otp", methods=["GET", "POST"])
def otp_verification():
    if "pending_username" not in session:
        return redirect(url_for("login"))

    username   = session["pending_username"]
    risk_level = session.get("risk_level", "low")
    risk_score = session.get("risk_score", 0.0)

    stored   = otp_store.get(username)
    demo_otp = stored["otp"] if stored else None   # shown in demo only

    if request.method == "POST":
        entered = request.form.get("otp", "").strip()

        if not stored or time.time() > stored["expires"]:
            otp_store.pop(username, None)
            session.clear()
            return render_template("otp.html",
                                   error="OTP expired. Please log in again.",
                                   risk_level=risk_level)

        if entered == stored["otp"]:
            otp_store.pop(username, None)
            update_last_log_outcome(username, "success")
            session.pop("pending_username", None)
            return render_template(
                "success.html",
                username=username,
                risk_level=risk_level,
                risk_score=round(risk_score, 3),
            )

        return render_template("otp.html",
                               error="Incorrect OTP — try again.",
                               risk_level=risk_level,
                               demo_otp=demo_otp)

    return render_template("otp.html", risk_level=risk_level, demo_otp=demo_otp)


@app.route("/dashboard")
def dashboard():
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM login_logs ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", logs=logs)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    ensure_model_ready()
    app.run(debug=True)
