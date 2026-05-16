# AI/ML-Enhanced Multi-Factor Authentication System

## Project Overview

This prototype implements an **adaptive MFA system** that uses a trained **Random Forest classifier** to assess the risk of every login attempt in real time and apply a proportional mitigation response.

```
User enters username + password
         ↓
System verifies password (bcrypt hash)
         ↓
AI/ML engine evaluates 5 behavioural features
         ↓
Low risk   → OTP MFA  (standard flow)
Medium     → OTP MFA + 2-second artificial delay
High risk  → Temporary 60-second block
         ↓
If OTP correct → Access Granted
```

---

## Group Members & Roles

| Member | Role | Responsible For |
|--------|------|-----------------|
| Naashiruddin | System Designer & Security Lead | Problem statement, architecture, risk logic |
| Harold | AI/ML Developer | Random Forest algorithm, feature engineering, pseudocode |
| Aida | Full-Stack Developer | Flask app, login UI, OTP integration |
| Sabrina | QA Analyst & Technical Writer | Testing, effectiveness analysis, future improvements |


---

## System Components

| Component | Technology |
|-----------|-----------|
| Web framework | Flask |
| Password hashing | Werkzeug bcrypt |
| MFA mechanism | 6-digit time-limited OTP (5-min expiry) |
| AI/ML classifier | Random Forest — scikit-learn |
| Database | SQLite (audit log + user store) |
| Frontend | Jinja2 templates + CSS |

---

## ML Features

The Random Forest is trained on synthetic login-attempt data with 5 behavioural features:

| Feature | Description |
|---------|-------------|
| `failed_attempts` | Prior failed logins for this user (capped at 10) |
| `short_interval` | 1 if this attempt came < 5 s after the previous one |
| `unknown_device` | 1 if device is not in the user's known-device list |
| `unusual_hour` | 1 if login hour is between 23:00 and 05:59 |
| `password_match` | 1 if the submitted password was correct |

---

## Setup & Run — Windows

> Requires **Python 3.10 or later**. Download from [python.org](https://www.python.org/downloads/).

Open **Command Prompt** or **PowerShell** and run:

```powershell
# 1. Clone the repository
git clone https://github.com/aidarollin/mfa-security-project.git
cd mfa-security-project

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the virtual environment
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
python app.py
```

Open your browser at **http://127.0.0.1:5000**

The ML model trains automatically on first launch (takes ~5 seconds).

### Deactivate when done

```powershell
deactivate
```

---

## Setup & Run — macOS / Linux

> Requires **Python 3.10 or later**. Check with `python3 --version`.  
> Install via [python.org](https://www.python.org/downloads/) or Homebrew: `brew install python`.

Open **Terminal** and run:

```bash
# 1. Clone the repository
git clone https://github.com/aidarollin/mfa-security-project.git
cd mfa-security-project

# 2. Create a virtual environment
python3 -m venv venv

# 3. Activate the virtual environment
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
python app.py
```

Open your browser at **http://127.0.0.1:5000**

### Deactivate when done

```bash
deactivate
```

---

## Demo Credentials

| Username | Password | Known Device |
|----------|----------|-------------|
| `student1` | `Secure123!` | `laptop-01` |
| `student2` | `StrongPass456!` | `phone-02` |
| `admin` | `Admin@789` | `workstation-01` |

> **OTP is shown in two places (demo mode):**
> - On the OTP verification page in the browser
> - Printed to the terminal where `python app.py` is running

---

## Project File Structure

```
mfa-security-project/
├── app.py                  Flask application & all routes
├── ml_model.py             Random Forest training + inference
├── simulate_attack.py      Automated test / demo script (Question 4)
├── requirements.txt        Python dependencies
├── docs/
│   ├── member1_system_design.md    Member 1 — architecture & problem statement
│   ├── member2_algorithm.md        Member 2 — ML algorithm & pseudocode
│   ├── member3_implementation.md   Member 3 — implementation guide
│   └── member4_testing.md          Member 4 — testing & analysis
├── templates/
│   ├── base.html           Shared layout
│   ├── login.html          Login page (username + password + device)
│   ├── otp.html            OTP verification page
│   ├── blocked.html        Account blocked page
│   ├── success.html        Successful login page
│   └── dashboard.html      Security audit log (admin view)
├── static/
│   └── style.css           Stylesheet
├── model/                  (auto-created) Trained model .pkl file
└── instance/               (auto-created) SQLite database
```

---

## Testing Scenarios (Question 4)

### Manual testing table

| Scenario | Username | Password | Device | Expected Result |
|----------|----------|----------|--------|-----------------|
| Normal login | student1 | Secure123! | laptop-01 | OTP sent → Success |
| Wrong password | student1 | badpass | laptop-01 | Denied (attempt 1/5) |
| Rapid brute-force ×5 | student1 | wrong | laptop-01 | Blocked 60 s |
| Correct pw, unknown device | student2 | StrongPass456! | hacker-pc | Medium/High risk, OTP forced |
| Correct pw, known device | admin | Admin@789 | workstation-01 | Low risk, OTP → Success |

### Automated attack simulation

With the Flask app **already running** in one terminal:

```bash
# Windows
python simulate_attack.py

# macOS / Linux
python3 simulate_attack.py
```

Then view the full audit log at **http://127.0.0.1:5000/dashboard**

---

## Mitigation Mechanisms

| Mechanism | Trigger | Effect |
|-----------|---------|--------|
| OTP MFA | Every successful password | Attacker still needs second factor |
| 2-second delay | Medium risk score | Slows automated guessing tools |
| Account block (60 s) | ≥ 5 failures OR high risk score | Stops brute-force / credential stuffing |
| Risk-based escalation | Multiple simultaneous anomalies | Higher risk = stronger response |

---

## Troubleshooting

### "ModuleNotFoundError" on launch

Make sure the virtual environment is activated before running:
- Windows: `venv\Scripts\activate`
- macOS/Linux: `source venv/bin/activate`

Then: `pip install -r requirements.txt`

### Port 5000 already in use

```bash
# Use a different port
python app.py --port 5001
```

Or on macOS, disable AirPlay Receiver in **System Settings → General → AirDrop & Handoff**.

### Model not training / sklearn error

```bash
pip install --upgrade scikit-learn numpy joblib
```

### Database reset (fresh start)

Delete the `instance/` folder and restart `python app.py`. The database and demo users are recreated automatically.

---

## Security Notes

- Passwords are stored as **bcrypt hashes** — never plain text.
- The ML model trains on a synthetic dataset in `ml_model.py`. Replace with real attack-log data for production.
- OTP delivery is simulated (console + browser). Integrate `smtplib` or Twilio for real email/SMS delivery.
- The `login_tracker` dictionary is in-memory; use Redis or a database table for multi-worker / persistent state.
- `app.secret_key` must be replaced with a secure random value in production.
