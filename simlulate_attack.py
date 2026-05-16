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

print(f"\n{'='*52}")
print(f"  Done.  View results at {BASE}/dashboard")
print(f"{'='*52}\n")
