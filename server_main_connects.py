# server.py
import os
import sqlite3
import hashlib
import binascii
import json
import base64
from flask import Flask, request, make_response
from typing import Tuple

# ────────────────────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────────────────────

DB_FILENAME       = "users.db"
PBKDF2_ITERATIONS = 100_000
HASH_NAME         = "sha256"

# A shared secret key (make this long and random in production).
# For example, set via Railway’s environment variables:
#   SHARED_SECRET=your_very_random_string_here
SHARED_KEY = os.environ.get("SHARED_SECRET", "please_change_this_to_a_random_value")


# ────────────────────────────────────────────────────────────────────────────────
#   Utility: Password hashing (PBKDF2) and verification (no third‐party libraries)
# ────────────────────────────────────────────────────────────────────────────────

def generate_salt(length: int = 16) -> bytes:
    return os.urandom(length)

def hash_password(password: str, salt: bytes) -> bytes:
    """
    Derive a SHA-256–based PBKDF2 key from `password`+`salt`.
    Returns the raw bytes of the derived key.
    """
    pwd_bytes = password.encode("utf-8")
    dk = hashlib.pbkdf2_hmac(HASH_NAME, pwd_bytes, salt, PBKDF2_ITERATIONS)
    return dk

def verify_password(stored_hash_hex: str, stored_salt_hex: str, provided_password: str) -> bool:
    salt       = binascii.unhexlify(stored_salt_hex)
    expected   = binascii.unhexlify(stored_hash_hex)
    provided_h = hash_password(provided_password, salt)
    # Use compare_digest to avoid timing attacks
    return hashlib.compare_digest(expected, provided_h)


# ────────────────────────────────────────────────────────────────────────────────
#   Utility: Simple XOR “cipher” + Base64
#   (This is NOT industrial‐strength encryption—use only for learning/demo.)
#   We repeat the shared key to match the plaintext length, XOR, then Base64‐encode.
# ────────────────────────────────────────────────────────────────────────────────

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR‐encrypt/decrypt `data` with `key` (which is repeated as needed).
    If you call this twice with the same key, you get the original data back.
    """
    out = bytearray(len(data))
    key_len = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % key_len]
    return bytes(out)

def encrypt_and_encode(plaintext: str) -> str:
    """
    1) Convert plaintext → UTF-8 bytes
    2) XOR with SHARED_KEY (in UTF-8)
    3) Base64‐encode the result
    """
    raw      = plaintext.encode("utf-8")
    key_bytes = SHARED_KEY.encode("utf-8")
    xored    = _xor_bytes(raw, key_bytes)
    b64      = base64.b64encode(xored)
    return b64.decode("ascii")

def decode_and_decrypt(cipher_b64: str) -> str:
    """
    1) Base64‐decode the input
    2) XOR with SHARED_KEY (in UTF-8)
    3) Decode result as UTF-8
    """
    try:
        xored    = base64.b64decode(cipher_b64)
        key_bytes = SHARED_KEY.encode("utf-8")
        raw      = _xor_bytes(xored, key_bytes)
        return raw.decode("utf-8")
    except Exception:
        # If anything fails (bad base64, bad key…), return an empty string
        return ""


# ────────────────────────────────────────────────────────────────────────────────
#   Initialize / migrate the SQLite database
# ────────────────────────────────────────────────────────────────────────────────

def init_db():
    """
    Create a 'users' table if it doesn’t already exist.
    Fields:
      - id            INTEGER PRIMARY KEY AUTOINCREMENT
      - username      TEXT UNIQUE NOT NULL
      - password_hash TEXT NOT NULL  (hex‐encoded)
      - salt          TEXT NOT NULL  (hex‐encoded)
      - plan          TEXT NOT NULL
      - credit_card   TEXT NOT NULL
    """
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
#   Flask App
# ────────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)

@app.before_first_request
def on_startup():
    init_db()


@app.route("/signup", methods=["POST"])
def signup():
    """
    Expects: An application/x-www-form-urlencoded POST body containing a single field:
        data=<base64_of_xor_encrypted_JSON>
    The JSON (after decrypting) must be:
        {
          "username": "<str>",
          "password": "<str>",
          "plan": "<str>",
          "credit_card": "<str>"
        }
    Returns (always encrypted in the same way):
    On success (HTTP 201):
        {
          "success": true,
          "message": "Registered successfully"
        }
    On error (HTTP 4xx or 5xx):
        { "success": false, "message": "<explanation>" }
    """
    cipher_b64 = request.form.get("data", "")
    if not cipher_b64:
        resp = {"success": False, "message": "No data provided"}
        return _encrypted_response(resp, 400)

    # 1) Decrypt client’s payload
    plaintext = decode_and_decrypt(cipher_b64)
    if not plaintext:
        resp = {"success": False, "message": "Could not decrypt payload"}
        return _encrypted_response(resp, 400)

    # 2) Parse JSON
    try:
        payload = json.loads(plaintext)
    except Exception:
        resp = {"success": False, "message": "Invalid JSON"}
        return _encrypted_response(resp, 400)

    username   = payload.get("username", "").strip()
    password   = payload.get("password", "").strip()
    plan       = payload.get("plan", "").strip()
    credit_card= payload.get("credit_card", "").strip()

    # 3) Server‐side validation
    if not username:
        resp = {"success": False, "message": "Username is required"}
        return _encrypted_response(resp, 400)
    if not password:
        resp = {"success": False, "message": "Password is required"}
        return _encrypted_response(resp, 400)

    valid_plans = {"free", "0.0$ per month", "why does the plan options even exist"}
    if plan not in valid_plans:
        resp = {"success": False, "message": "Invalid plan selected"}
        return _encrypted_response(resp, 400)

    if not credit_card:
        resp = {"success": False, "message": "Credit card is required"}
        return _encrypted_response(resp, 400)

    # 4) Hash+salt the password
    salt_bytes  = generate_salt()
    hash_bytes  = hash_password(password, salt_bytes)
    salt_hex    = binascii.hexlify(salt_bytes).decode("ascii")
    hash_hex    = binascii.hexlify(hash_bytes).decode("ascii")

    # 5) Insert into DB (parameterized query → no SQL injection)
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
        resp = {"success": False, "message": "Username already exists"}
        return _encrypted_response(resp, 409)
    except Exception as e:
        resp = {"success": False, "message": f"Database error: {str(e)}"}
        return _encrypted_response(resp, 500)

    resp = {"success": True, "message": "Registered successfully"}
    return _encrypted_response(resp, 201)


@app.route("/login", methods=["POST"])
def login():
    """
    Expects: An application/x-www-form-urlencoded POST body containing:
        data=<base64_of_xor_encrypted_JSON>
    The JSON (after decrypting) must be:
        {
          "username": "<str>",
          "password": "<str>"
        }
    Returns (encrypted) JSON:
      On success (HTTP 200): { "success": true,  "message": "Login successful" }
      On bad credentials (HTTP 401):  { "success": false, "message": "Invalid username or password" }
      On missing fields (HTTP 400):   { "success": false, "message": "<reason>" }
    """
    cipher_b64 = request.form.get("data", "")
    if not cipher_b64:
        resp = {"success": False, "message": "No data provided"}
        return _encrypted_response(resp, 400)

    plaintext = decode_and_decrypt(cipher_b64)
    if not plaintext:
        resp = {"success": False, "message": "Could not decrypt payload"}
        return _encrypted_response(resp, 400)

    try:
        payload = json.loads(plaintext)
    except Exception:
        resp = {"success": False, "message": "Invalid JSON"}
        return _encrypted_response(resp, 400)

    username = payload.get("username", "").strip()
    password = payload.get("password", "").strip()

    if not username:
        resp = {"success": False, "message": "Username is required"}
        return _encrypted_response(resp, 400)
    if not password:
        resp = {"success": False, "message": "Password is required"}
        return _encrypted_response(resp, 400)

    # Fetch the stored hash+salt from the database
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
        resp = {"success": False, "message": "Invalid username or password"}
        return _encrypted_response(resp, 401)

    stored_hash_hex, stored_salt_hex = row
    if not verify_password(stored_hash_hex, stored_salt_hex, password):
        resp = {"success": False, "message": "Invalid username or password"}
        return _encrypted_response(resp, 401)

    resp = {"success": True, "message": "Login successful"}
    return _encrypted_response(resp, 200)


def _encrypted_response(payload_dict: dict, http_status: int) -> Tuple[str,int,dict]:
    """
    JSON‐dump the payload_dict, encrypt it (XOR+Base64), and return an HTTP response.
    Content‐Type is text/plain because we’re sending a Base64 string, not raw JSON.
    """
    plaintext_json = json.dumps(payload_dict)
    encrypted_b64  = encrypt_and_encode(plaintext_json)
    response       = make_response(encrypted_b64, http_status)
    response.headers["Content-Type"] = "text/plain"
    return response


if __name__ == "__main__":
    # Run on port 5000 over plain HTTP (no SSL here)
    # In production on Railway, it will be exposed as https://your-app.up.railway.app automatically
    app.run(host="0.0.0.0", port=5000)
