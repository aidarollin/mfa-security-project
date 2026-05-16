import requests
import time

BASE    = "http://127.0.0.1:5000"
DIVIDER = "─" * 52


def _post(label, username, password, device_id, session=None):
    s = session or requests.Session()
    r = s.post(
        BASE + "/",
        data={"username": username, "password": password, "device_id": device_id},
        allow_redirects=False,
    )
    loc = r.headers.get("Location", "")
    if r.status_code == 302 and "/otp" in loc:
        status = "OTP page → MFA triggered"
    elif r.status_code == 200 and "Blocked" in r.text:
        status = "BLOCKED"
    elif r.status_code == 200 and "Invalid" in r.text:
        status = "Denied (wrong credentials)"
    else:
        status = f"HTTP {r.status_code}"
    print(f"  {label:40s} → {status}")
    return r, s


print(f"\n{'='*52}")
print("  AI/ML-MFA System — Attack Scenario Simulator")
print(f"{'='*52}")
print(f"  Dashboard: {BASE}/dashboard\n")

# ── Scenario 1: Normal login ──────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("  Scenario 1 — Normal Login")
print(DIVIDER)
_post("student1 / Secure123! / laptop-01 (known)", "student1", "Secure123!", "laptop-01")

time.sleep(1.5)

# ── Scenario 2: Incorrect password ───────────────────────────────────────────
print(f"\n{DIVIDER}")
print("  Scenario 2 — Single Wrong Password")
print(DIVIDER)
_post("student2 / wrongpass / phone-02", "student2", "wrongpass", "phone-02")

time.sleep(1.5)

# ── Scenario 3: Rapid brute-force (triggers block) ────────────────────────────
print(f"\n{DIVIDER}")
print("  Scenario 3 — Rapid Brute-Force Attack (5 quick attempts)")
print(DIVIDER)
sess = requests.Session()
attack_passwords = ["abc", "123", "password", "qwerty", "letmein", "admin"]
for i, pw in enumerate(attack_passwords, 1):
    r, sess = _post(f"Attempt {i}: student1 / {pw}", "student1", pw, "laptop-01", session=sess)
    time.sleep(0.3)   # rapid interval — triggers short_interval feature

time.sleep(1.5)

# ── Scenario 4: Unknown device ────────────────────────────────────────────────
print(f"\n{DIVIDER}")
print("  Scenario 4 — Correct Password, Unknown Device")
print(DIVIDER)
_post("student2 / StrongPass456! / hacker-device", "student2", "StrongPass456!", "hacker-device")

# ── Scenario 5: Correct password, unknown device ─────────────────────────────
print(f"\n{DIVIDER}")
print("  Scenario 5 — Correct Password, Unknown Device (medium/high risk)")
print(DIVIDER)
_post("student1 / Secure123! / hacker-device (unknown)", "student1", "Secure123!", "hacker-device")

time.sleep(1.5)

# ── Scenario 6: Dictionary attack (sequential common passwords) ───────────────
print(f"\n{DIVIDER}")
print("  Scenario 6 — Dictionary Attack (common password list)")
print(DIVIDER)
sess2 = requests.Session()
common_passwords = ["password", "123456", "admin", "letmein", "qwerty", "monkey", "dragon"]
for i, pw in enumerate(common_passwords, 1):
    r, sess2 = _post(f"Attempt {i}: admin / {pw}", "admin", pw, "unknown-device", session=sess2)
    time.sleep(0.2)

print(f"\n{'='*52}")
print("  Testing Summary")
print(f"{'='*52}")
print("  Scenario 1  — Normal login            → expects: OTP MFA triggered")
print("  Scenario 2  — Single wrong password   → expects: denied (attempt 1/5)")
print("  Scenario 3  — Rapid brute-force       → expects: BLOCKED after 5 fails")
print("  Scenario 4  — Unknown device          → expects: OTP MFA (medium risk)")
print("  Scenario 5  — Known pw, unknown dev   → expects: OTP MFA (elevated risk)")
print("  Scenario 6  — Dictionary attack       → expects: BLOCKED after 5 fails")
print(f"\n  View full results at {BASE}/dashboard")
print(f"{'='*52}\n")
