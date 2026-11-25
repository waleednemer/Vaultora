"""Password manager API.

Zero-knowledge design: the browser derives keys from the master password and
encrypts every entry (AES-GCM) before upload. This server only ever stores
ciphertext, plus a hash of an *auth key* that is derived separately from the
encryption key, so it can verify a login without being able to decrypt anything.
"""
import os
import re
import time
from collections import defaultdict, deque
from contextlib import closing
from functools import wraps

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()
app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is required (openssl rand -hex 32)")
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="vault-session")

SESSION_SECONDS = 30 * 60
MIN_ITERATIONS = 100_000
MAX_ITERATIONS = 10_000_000
MAX_DATA_LEN = 20_000
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 60  # seconds

B64_SALT = re.compile(r"^[A-Za-z0-9+/]{22}==$")  # 16 bytes
B64_KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")  # 32 bytes
B64_DATA = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

_fails = defaultdict(deque)  # client ip -> timestamps of failed logins


def connect():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "vaultdb"),
        user=os.getenv("DB_USER", "vaultuser"),
        password=os.getenv("DB_PASSWORD", "vaultpass"),
    )


def query(sql, params=(), fetch="all"):
    with closing(connect()) as conn, conn:  # noqa: SIM117
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            if fetch == "none":
                return None
            return cur.fetchall() if fetch == "all" else cur.fetchone()


# ---------- validation ----------
def clean_setup(data):
    salt, key, iters = data.get("salt"), data.get("auth_key"), data.get("iterations")
    if not isinstance(salt, str) or not B64_SALT.match(salt):
        return None, "salt غير صالح"
    if not isinstance(key, str) or not B64_KEY.match(key):
        return None, "auth_key غير صالح"
    if not isinstance(iters, int) or isinstance(iters, bool) or not MIN_ITERATIONS <= iters <= MAX_ITERATIONS:
        return None, "عدد التكرارات غير صالح"
    return {"salt": salt, "auth_key": key, "iterations": iters}, None


def clean_entry(data):
    blob = data.get("data")
    if not isinstance(blob, str) or not blob or len(blob) > MAX_DATA_LEN or not B64_DATA.match(blob):
        return None, "بيانات غير صالحة"
    return blob, None


# ---------- auth ----------
def client_ip():
    return request.headers.get("X-Real-IP") or request.remote_addr or "unknown"


def too_many_fails(ip):
    now = time.monotonic()
    q = _fails[ip]
    while q and now - q[0] > LOGIN_WINDOW:
        q.popleft()
    return len(q) >= LOGIN_MAX_FAILS


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        try:
            serializer.loads(token, max_age=SESSION_SECONDS)
        except BadSignature:  # includes SignatureExpired
            return jsonify(error="الجلسة غير صالحة. سجّل الدخول من جديد."), 401
        return view(*args, **kwargs)

    return wrapper


@app.after_request
def no_store(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ---------- routes ----------
@app.get("/api/health")
def health():
    return jsonify(status="ok")


@app.get("/api/vault")
def vault_info():
    row = query("SELECT salt, iterations FROM vault WHERE id = 1", fetch="one")
    if not row:
        return jsonify(initialized=False)
    return jsonify(initialized=True, salt=row["salt"], iterations=row["iterations"])


@app.post("/api/vault")
def vault_setup():
    data, err = clean_setup(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    row = query(
        "INSERT INTO vault (id, salt, iterations, auth_hash) VALUES (1, %s, %s, %s) "
        "ON CONFLICT (id) DO NOTHING RETURNING id",
        (data["salt"], data["iterations"], generate_password_hash(data["auth_key"])),
        "one",
    )
    if not row:
        return jsonify(error="الخزنة موجودة مسبقًا"), 409
    return jsonify(initialized=True), 201


@app.post("/api/login")
def login():
    ip = client_ip()
    if too_many_fails(ip):
        return jsonify(error="محاولات كثيرة. انتظر دقيقة ثم حاول مجددًا."), 429
    key = (request.get_json(silent=True) or {}).get("auth_key")
    row = query("SELECT auth_hash FROM vault WHERE id = 1", fetch="one")
    if not row:
        return jsonify(error="الخزنة غير مهيأة بعد"), 404
    if not isinstance(key, str) or not check_password_hash(row["auth_hash"], key):
        _fails[ip].append(time.monotonic())
        return jsonify(error="كلمة السر الرئيسية غير صحيحة"), 401
    _fails.pop(ip, None)
    return jsonify(token=serializer.dumps("vault"), expires_in=SESSION_SECONDS)


@app.get("/api/entries")
@require_auth
def list_entries():
    return jsonify(query("SELECT id, data, updated_at::text AS updated_at FROM entries ORDER BY id DESC"))


@app.post("/api/entries")
@require_auth
def create_entry():
    blob, err = clean_entry(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    row = query(
        "INSERT INTO entries (data) VALUES (%s) RETURNING id, data, updated_at::text AS updated_at",
        (blob,),
        "one",
    )
    return jsonify(row), 201


@app.put("/api/entries/<int:entry_id>")
@require_auth
def update_entry(entry_id):
    blob, err = clean_entry(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    row = query(
        "UPDATE entries SET data = %s, updated_at = NOW() WHERE id = %s "
        "RETURNING id, data, updated_at::text AS updated_at",
        (blob, entry_id),
        "one",
    )
    return (jsonify(row), 200) if row else (jsonify(error="العنصر غير موجود"), 404)


@app.delete("/api/entries/<int:entry_id>")
@require_auth
def delete_entry(entry_id):
    row = query("DELETE FROM entries WHERE id = %s RETURNING id", (entry_id,), "one")
    return ("", 204) if row else (jsonify(error="العنصر غير موجود"), 404)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5051, debug=os.getenv("FLASK_DEBUG") == "1")
