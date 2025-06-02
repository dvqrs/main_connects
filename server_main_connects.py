import os
import sqlite3
import hashlib
import hmac      # ← import hmac for compare_digest
import binascii
import json
import base64
from flask import Flask, request, make_response

# ────────────────────────────────────────────────────────────────────────────────
# Configuration (unchanged)
# ────────────────────────────────────────────────────────────────────────────────

DB_FILENAME       = "users.db"
PBKDF2_ITERATIONS = 100_000
HASH_NAME         = "sha256"

SHARED_KEY = os.environ.get("SHARED_SECRET", None)
if SHARED_KEY is None:
    raise RuntimeError("You must set SHARED_SECRET in the environment!")

# ────────────────────────────────────────────────────────────────────────────────
# Password‐hashing helpers
# ────────────────────────────────────────────────────────────────────────────────

def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)

def hash_password(password: str, salt: bytes) -> bytes:
    pwd_bytes = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac(HASH_NAME, pwd_bytes, salt, PBKDF2_ITERATIONS)
    return dk

def verify_password(stored_hash_hex: str, stored_salt_hex: str, provided_password: str) -> bool:
    """
    Compare stored hash (hex) + salt (hex) against hash of provided_password.
    Uses hmac.compare_digest to avoid timing attacks.
    """
    salt = binascii.unhexlify(stored_salt_hex)
    expected_hash = binascii.unhexlify(stored_hash_hex)
    provided_hash = hash_password(provided_password, salt)
    # Use hmac.compare_digest instead of hashlib.compare_digest
    return hmac.compare_digest(expected_hash, provided_hash)

# ────────────────────────────────────────────────────────────────────────────────
# XOR + Base64 “encryption” helpers (unchanged)
# ────────────────────────────────────────────────────────────────────────────────

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    out = bytearray(len(data))
    key_len = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % key_len]
    return bytes(out)

def encrypt_and_encode(plaintext: str) -> str:
    raw       = plaintext.encode("utf-8")
    key_bytes = SHARED_KEY.encode("utf-8")
    xored     = _xor_bytes(raw, key_bytes)
    b64       = base64.b64encode(xored)
    return b64.decode("ascii")

def decode_and_decrypt(cipher_b64: str) -> str:
    try:
        xored     = base64.b64decode(cipher_b64)
        key_bytes = SHARED_KEY.encode("utf-8")
        raw       = _xor_bytes(xored, key_bytes)
        return raw.decode("utf-8")
    except Exception:
        return ""

# ────────────────────────────────────────────────────────────────────────────────
# Database setup (unchanged)
# ────────────────────────────────────────────────────────────────────────────────

def init_db():
    conn   = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            plan          TEXT NOT NULL,
            credit_card   TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# ────────────────────────────────────────────────────────────────────────────────
# Flask app
# ────────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

# Initialize DB immediately, instead of using @before_first_request
init_db()

@app.route("/signup", methods=["POST"])
def signup():
    cipher_b64 = request.form.get("data", "")
    if not cipher_b64:
        return _encrypted_response({"success": False, "message": "No data provided"}, 400)

    plaintext = decode_and_decrypt(cipher_b64)
    if not plaintext:
        return _encrypted_response({"success": False, "message": "Could not decrypt payload"}, 400)

    try:
        payload = json.loads(plaintext)
    except Exception:
        return _encrypted_response({"success": False, "message": "Invalid JSON"}, 400)

    username    = payload.get("username", "").strip()
    password    = payload.get("password", "").strip()
    plan        = payload.get("plan", "").strip()
    credit_card = payload.get("credit_card", "").strip()

    if not username:
        return _encrypted_response({"success": False, "message": "Username is required"}, 400)
    if not password:
        return _encrypted_response({"success": False, "message": "Password is required"}, 400)

    valid_plans = {"free", "0.0$ per month", "why does the plan options even exist"}
    if plan not in valid_plans:
        return _encrypted_response({"success": False, "message": "Invalid plan selected"}, 400)
    if not credit_card:
        return _encrypted_response({"success": False, "message": "Credit card is required"}, 400)

    salt_bytes = generate_salt()
    hash_bytes = hash_password(password, salt_bytes)
    salt_hex   = binascii.hexlify(salt_bytes).decode("ascii")
    hash_hex   = binascii.hexlify(hash_bytes).decode("ascii")

    try:
        conn   = sqlite3.connect(DB_FILENAME)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password_hash, salt, plan, credit_card)
            VALUES (?, ?, ?, ?, ?)
        """, (username, hash_hex, salt_hex, plan, credit_card))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return _encrypted_response({"success": False, "message": "Username already exists"}, 409)
    except Exception as e:
        return _encrypted_response({"success": False, "message": f"Database error: {e}"}, 500)

    return _encrypted_response({"success": True, "message": "Registered successfully"}, 201)

@app.route("/login", methods=["POST"])
def login():
    cipher_b64 = request.form.get("data", "")
    if not cipher_b64:
        return _encrypted_response({"success": False, "message": "No data provided"}, 400)

    plaintext = decode_and_decrypt(cipher_b64)
    if not plaintext:
        return _encrypted_response({"success": False, "message": "Could not decrypt payload"}, 400)

    try:
        payload = json.loads(plaintext)
    except Exception:
        return _encrypted_response({"success": False, "message": "Invalid JSON"}, 400)

    username = payload.get("username", "").strip()
    password = payload.get("password", "").strip()

    if not username:
        return _encrypted_response({"success": False, "message": "Username is required"}, 400)
    if not password:
        return _encrypted_response({"success": False, "message": "Password is required"}, 400)

    conn   = sqlite3.connect(DB_FILENAME)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT password_hash, salt
          FROM users
         WHERE username = ?
    """, (username,))
    row = cursor.fetchone()
    conn.close()

    if row is None:
        return _encrypted_response({"success": False, "message": "Invalid username or password"}, 401)

    stored_hash_hex, stored_salt_hex = row
    if not verify_password(stored_hash_hex, stored_salt_hex, password):
        return _encrypted_response({"success": False, "message": "Invalid username or password"}, 401)

    return _encrypted_response({"success": True, "message": "Login successful"}, 200)

def _encrypted_response(payload_dict, http_status):
    plaintext_json = json.dumps(payload_dict)
    encrypted_b64  = encrypt_and_encode(plaintext_json)
    response       = make_response(encrypted_b64, http_status)
    response.headers["Content-Type"] = "text/plain"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
