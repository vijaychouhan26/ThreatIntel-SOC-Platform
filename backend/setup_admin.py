import os
import getpass
import secrets
import time
import pyotp
import qrcode
from auth import hash_password

username = input("Admin username [admin]: ").strip() or "admin"
mfa_enabled = os.getenv("MFA_ENABLED", "true").lower() in {"1", "true", "yes"}

print("=== Admin Setup ===")
print(f"Creating/resetting local admin account: {username}")
pw1 = getpass.getpass("Naya password daal: ")
pw2 = getpass.getpass("Password dobara: ")
if pw1 != pw2:
    print("Password match nahi hua. Dobara chala.")
    raise SystemExit(1)
if len(pw1) < 8:
    print("Password kam se kam 8 characters ka rakh.")
    raise SystemExit(1)

hashed = hash_password(pw1)

# JWT secret (random, strong)
jwt_secret = secrets.token_urlsafe(48)

# .env me daalo (purane auth lines hata ke)
env_path = ".env"
lines = []
if os.path.exists(env_path):
    with open(env_path) as f:
        lines = [l for l in f if not l.startswith(("ADMIN_USER", "ADMIN_PASS_HASH", "JWT_SECRET", "JWT_NOT_BEFORE"))]

lines.append(f"ADMIN_USER={username}\n")
lines.append(f"ADMIN_PASS_HASH={hashed}\n")
lines.append(f"JWT_SECRET={jwt_secret}\n")
lines.append(f"JWT_NOT_BEFORE={int(time.time())}\n")

if mfa_enabled:
    mfa_secret = pyotp.random_base32()
    lines = [line for line in lines if not line.startswith("MFA_SECRET")]
    lines.append(f"MFA_SECRET={mfa_secret}\n")

with open(env_path, "w") as f:
    f.writelines(lines)

if mfa_enabled:
    # QR code -- terminal me dikhao (phone se scan karega)
    uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name="ThreatIntel")
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make()
    print("\n=== MFA QR Code -- Google Authenticator / Authy se scan kar ===\n")
    qr.print_ascii(invert=True)
    print(f"\nAgar QR na scan ho, ye secret manually daal app me:\n  {mfa_secret}\n")
else:
    print("\nMFA is disabled. Sign in with this username and password only.\n")
print(f"Setup done! Username: {username}")
print("Restart the API after setup. Existing login sessions are invalidated.")
