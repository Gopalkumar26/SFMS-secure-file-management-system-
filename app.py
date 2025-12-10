# app.py (full updated)
import os
import sqlite3
import io
import binascii
import hashlib
import secrets
import datetime
import functools
import mimetypes
import qrcode
import base64

from flask import (
    Flask, request, redirect, url_for, render_template, flash,
    session, send_file, g, abort
)
import bcrypt
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Configuration ----------
APP_SECRET = os.environ.get("APP_SECRET") or secrets.token_hex(32)
MASTER_KEY_HEX = os.environ.get("MASTER_KEY_HEX")  # 64 hex chars recommended (32 bytes)
if not MASTER_KEY_HEX:
    # generate a deterministic dev key only if not provided (not for production)
    MASTER_KEY_HEX = hashlib.sha256(b"dev-master-key").hexdigest()[:64]
MASTER_KEY = binascii.unhexlify(MASTER_KEY_HEX)
if len(MASTER_KEY) != 32:
    raise RuntimeError("MASTER_KEY must be 32 bytes (64 hex chars) in env var MASTER_KEY_HEX")

UPLOAD_FOLDER = "encrypted_files"
QUARANTINE_FOLDER = "quarantine_files"
DB_PATH = "sfms.db"
ALLOWED_EXT_BLOCKLIST = {".exe", ".bat", ".cmd", ".sh", ".scr", ".js"}  # block these
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB prototype limit

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

# ---------- Flask App ----------
app = Flask(__name__)
app.secret_key = APP_SECRET
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# ---------- DB helpers ----------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        totp_secret TEXT DEFAULT NULL,
        created_at TEXT NOT NULL
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        storage_name TEXT NOT NULL,
        nonce_hex TEXT NOT NULL,
        file_hash TEXT NOT NULL,
        size INTEGER NOT NULL,
        uploaded_at TEXT NOT NULL,
        quarantined INTEGER DEFAULT 0,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    );
    """)
    # New: file_shares table to track sharing
    cur.execute("""
    CREATE TABLE IF NOT EXISTS file_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        owner_id INTEGER NOT NULL,
        shared_with_user INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(file_id) REFERENCES files(id),
        FOREIGN KEY(shared_with_user) REFERENCES users(id)
    );
    """)
    db.commit()

@app.teardown_appcontext
def close_db(error):
    db = getattr(g, "_db", None)
    if db:
        db.close()

# ---------- Auth helpers ----------
def hash_password(plain_pw: str) -> bytes:
    return bcrypt.hashpw(plain_pw.encode("utf-8"), bcrypt.gensalt())

def check_password(plain_pw: str, pw_hash: bytes) -> bool:
    # pw_hash comes from sqlite as bytes
    return bcrypt.checkpw(plain_pw.encode("utf-8"), pw_hash)

def login_user(user_row):
    session.clear()
    session['user_id'] = user_row['id']
    session['username'] = user_row['username']

def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return user

def require_login(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        return func(*args, **kwargs)
    return wrapper

# ---------- Crypto helpers (AES-GCM) ----------
def encrypt_bytes(plaintext: bytes) -> tuple[str, bytes]:
    """
    Returns (nonce_hex, ciphertext)
    Uses MASTER_KEY for prototype; in prod use per-file keys and KMS.
    """
    aesgcm = AESGCM(MASTER_KEY)
    nonce = os.urandom(12)  # 96-bit nonce for AESGCM
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return binascii.hexlify(nonce).decode(), ct

def decrypt_bytes(nonce_hex: str, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(MASTER_KEY)
    nonce = binascii.unhexlify(nonce_hex)
    pt = aesgcm.decrypt(nonce, ciphertext, None)
    return pt

# ---------- Malware detection (very simple prototype) ----------
def is_suspicious_by_extension(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT_BLOCKLIST

def magic_bytes_check(first_bytes: bytes) -> bool:
    # Example: detect windows PE header "MZ"
    if first_bytes.startswith(b"MZ"):
        return True
    return False

SIMPLE_SIGNATURES = [b"virus-test", b"malware", b"trojan"]

def simple_signature_scan(content: bytes) -> bool:
    sample = content[:4096].lower()
    for sig in SIMPLE_SIGNATURES:
        if sig in sample:
            return True
    return False

def scan_file_stream(stream) -> tuple[bool, str]:
    """
    Reads up to a small window and decides if suspicious.
    Returns (is_suspicious, reason)
    """
    first = stream.read(4096)
    stream.seek(0)
    if magic_bytes_check(first):
        return True, "magic-byte match (MZ/PE)"
    if simple_signature_scan(first):
        return True, "simple signature match"
    # extension checks happen outside
    return False, ""

# ---------- Authorization helpers ----------
def is_owner(file_row, user_id):
    return file_row['owner_id'] == user_id

def is_shared_with(file_id, user_id):
    db = get_db()
    r = db.execute("SELECT 1 FROM file_shares WHERE file_id=? AND shared_with_user=?", (file_id, user_id)).fetchone()
    return bool(r)

def is_authorized_to_view(file_row, user_id):
    # Owner or explicitly shared users may view (unless quarantined in some policies)
    if is_owner(file_row, user_id):
        return True
    if is_shared_with(file_row['id'], user_id):
        return True
    return False

# ---------- Routes ----------
@app.route("/")
def index():
    user = current_user()
    return render_template("index.html", user=user)

# ----- Register -----
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Provide username and password", "danger")
            return redirect(url_for("register"))

        db = get_db()
        try:
            pw_hash = hash_password(password)
            db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, pw_hash, datetime.datetime.utcnow().isoformat())
            )
            db.commit()
            flash("Registered. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists", "danger")
            return redirect(url_for("register"))
    return render_template("register.html")

# ----- Login -----
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        token = request.form.get("token", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not user:
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))
        if not check_password(password, user['password_hash']):
            flash("Invalid username or password", "danger")
            return redirect(url_for("login"))

        # if user enabled totp, require token
        if user['totp_secret']:
            if not token:
                flash("TOTP token required for this account", "warning")
                return redirect(url_for("login"))
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(token, valid_window=1):
                flash("Invalid TOTP token", "danger")
                return redirect(url_for("login"))

        login_user(user)
        flash("Logged in", "success")
        next_url = request.args.get("next") or url_for("dashboard")
        return redirect(next_url)
    return render_template("login.html")

# ----- Enable/Disable 2FA -----
@app.route("/2fa/setup")
@require_login
def twofa_setup():
    user = current_user()
    if user['totp_secret']:
        flash("2FA already enabled for your account", "info")
        return redirect(url_for("dashboard"))
    secret = pyotp.random_base32()
    # store temporary in session until user confirms
    session['temp_totp_secret'] = secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user['username'], issuer_name="SFMS-Prototype")
    return render_template("2fa_setup.html", uri=uri, secret=secret)

@app.route("/2fa/confirm", methods=["POST"])
@require_login
def twofa_confirm():
    code = request.form.get("code", "").strip()
    secret = session.get('temp_totp_secret')
    if not secret:
        flash("No 2FA setup in progress", "danger")
        return redirect(url_for("dashboard"))
    totp = pyotp.TOTP(secret)
    if totp.verify(code):
        db = get_db()
        db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, session['user_id']))
        db.commit()
        session.pop('temp_totp_secret', None)
        flash("2FA enabled", "success")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid code", "danger")
        return redirect(url_for("twofa_setup"))

@app.route("/2fa/disable", methods=["POST"])
@require_login
def twofa_disable():
    db = get_db()
    db.execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (session['user_id'],))
    db.commit()
    flash("2FA disabled", "info")
    return redirect(url_for("dashboard"))

# ----- Dashboard / List files -----
@app.route("/dashboard")
@require_login
def dashboard():
    db = get_db()
    # Owned files
    files = db.execute("SELECT * FROM files WHERE owner_id = ? ORDER BY uploaded_at DESC", (session['user_id'],)).fetchall()
    # Files shared with me (with owner's id for display)
    shared_files = db.execute("""
        SELECT f.*, s.owner_id as shared_owner
        FROM files f
        JOIN file_shares s ON f.id = s.file_id
        WHERE s.shared_with_user = ? 
        ORDER BY f.uploaded_at DESC
    """, (session['user_id'],)).fetchall()
    user = current_user()
    return render_template("dashboard.html", files=files, shared_files=shared_files, user=user)

# ----- Upload -----
@app.route("/upload", methods=["GET", "POST"])
@require_login
def upload():
    if request.method == "POST":
        if 'file' not in request.files:
            flash("No file part", "danger")
            return redirect(url_for("upload"))
        f = request.files['file']
        if f.filename == "":
            flash("No selected file", "danger")
            return redirect(url_for("upload"))
        filename = os.path.basename(f.filename)
        # basic extension blocklist
        if is_suspicious_by_extension(filename):
            # directly quarantine
            storage_name = secrets.token_hex(16) + ".quarantine"
            path = os.path.join(QUARANTINE_FOLDER, storage_name)
            f.save(path)
            # store metadata as quarantined
            db = get_db()
            file_hash = hashlib.sha256(open(path, "rb").read()).hexdigest()
            db.execute(
                "INSERT INTO files (owner_id, filename, storage_name, nonce_hex, file_hash, size, uploaded_at, quarantined) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (session['user_id'], filename, storage_name, "", file_hash, os.path.getsize(path), datetime.datetime.utcnow().isoformat())
            )
            db.commit()
            flash("File extension blocked and quarantined", "warning")
            return redirect(url_for("dashboard"))

        # read small chunk and run simple scanner
        f.stream.seek(0)
        is_susp, reason = scan_file_stream(f.stream)
        if is_susp:
            storage_name = secrets.token_hex(16) + ".quarantine"
            path = os.path.join(QUARANTINE_FOLDER, storage_name)
            f.save(path)
            db = get_db()
            file_hash = hashlib.sha256(open(path, "rb").read()).hexdigest()
            db.execute(
                "INSERT INTO files (owner_id, filename, storage_name, nonce_hex, file_hash, size, uploaded_at, quarantined) VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
                (session['user_id'], filename, storage_name, "", file_hash, os.path.getsize(path), datetime.datetime.utcnow().isoformat())
            )
            db.commit()
            flash(f"File flagged as suspicious ({reason}). Quarantined.", "danger")
            return redirect(url_for("dashboard"))

        # safe -> encrypt and store
        f.stream.seek(0)
        content = f.read()
        nonce_hex, ciphertext = encrypt_bytes(content)
        storage_name = secrets.token_hex(16) + ".enc"
        path = os.path.join(UPLOAD_FOLDER, storage_name)
        with open(path, "wb") as wf:
            wf.write(ciphertext)
        file_hash = hashlib.sha256(content).hexdigest()
        db = get_db()
        db.execute(
            "INSERT INTO files (owner_id, filename, storage_name, nonce_hex, file_hash, size, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session['user_id'], filename, storage_name, nonce_hex, file_hash, len(content), datetime.datetime.utcnow().isoformat())
        )
        db.commit()
        flash("Uploaded and encrypted", "success")
        return redirect(url_for("dashboard"))
    return render_template("upload.html")

# ----- Download -----
@app.route("/download/<int:file_id>")
@require_login
def download(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)

    # allow owner or shared-with users to download
    if not is_authorized_to_view(file_row, session['user_id']):
        abort(403)

    if file_row['quarantined']:
        # only owner allowed to see quarantined file metadata/list; shared users cannot download quarantined files
        if not is_owner(file_row, session['user_id']):
            flash("File is quarantined and cannot be downloaded", "danger")
            return redirect(url_for("dashboard"))

    folder = QUARANTINE_FOLDER if file_row['quarantined'] else UPLOAD_FOLDER
    path = os.path.join(folder, file_row['storage_name'])
    if not os.path.exists(path):
        flash("File not found on server", "danger")
        return redirect(url_for("dashboard"))
    with open(path, "rb") as rf:
        ciphertext = rf.read()
    try:
        plaintext = decrypt_bytes(file_row['nonce_hex'], ciphertext)
    except Exception:
        flash("Decryption failed or corrupted file", "danger")
        return redirect(url_for("dashboard"))
    return send_file(io.BytesIO(plaintext), download_name=file_row['filename'], as_attachment=True)

# ----- View in Browser (for readable files) -----
@app.route("/view/<int:file_id>")
@require_login
def view_file(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)

    # owner or shared user may view
    if not is_authorized_to_view(file_row, session['user_id']):
        abort(403)

    if file_row['quarantined'] and not is_owner(file_row, session['user_id']):
        flash("File is quarantined and cannot be viewed", "danger")
        return redirect(url_for("dashboard"))

    folder = QUARANTINE_FOLDER if file_row['quarantined'] else UPLOAD_FOLDER
    path = os.path.join(folder, file_row['storage_name'])
    if not os.path.exists(path):
        flash("File not found on server", "danger")
        return redirect(url_for("dashboard"))
    with open(path, "rb") as rf:
        ciphertext = rf.read()
    try:
        plaintext = decrypt_bytes(file_row['nonce_hex'], ciphertext)
    except Exception:
        flash("Decryption failed or corrupted file", "danger")
        return redirect(url_for("dashboard"))

    # try to guess MIME type from filename
    mime, _ = mimetypes.guess_type(file_row['filename'])
    if not mime:
        # default to plain text (safe choice for prototype)
        mime = "text/plain"

    return send_file(io.BytesIO(plaintext), download_name=file_row['filename'], as_attachment=False, mimetype=mime)

# ----- Edit (owner-only) -----
@app.route("/edit/<int:file_id>", methods=["GET", "POST"])
@require_login
def edit_file(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)

    # only owner can edit
    if not is_owner(file_row, session['user_id']):
        abort(403)

    if file_row['quarantined']:
        flash("Quarantined files cannot be edited", "danger")
        return redirect(url_for("dashboard"))

    folder = UPLOAD_FOLDER
    path = os.path.join(folder, file_row['storage_name'])
    if not os.path.exists(path):
        flash("File not found on server", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        # editing via text area: read 'content' field
        new_content_str = request.form.get("content", "")
        if new_content_str is None:
            flash("No content provided", "danger")
            return redirect(url_for("edit_file", file_id=file_id))
        new_content = new_content_str.encode("utf-8")
        # re-encrypt
        nonce_hex, ciphertext = encrypt_bytes(new_content)
        try:
            with open(path, "wb") as wf:
                wf.write(ciphertext)
            db.execute(
                "UPDATE files SET nonce_hex=?, file_hash=?, size=? WHERE id=?",
                (nonce_hex, hashlib.sha256(new_content).hexdigest(), len(new_content), file_id)
            )
            db.commit()
            flash("File updated successfully", "success")
            return redirect(url_for("dashboard"))
        except Exception as e:
            flash("Failed to update file", "danger")
            return redirect(url_for("edit_file", file_id=file_id))

    # GET -> load plaintext to show in editor
    with open(path, "rb") as rf:
        ciphertext = rf.read()
    try:
        plaintext_bytes = decrypt_bytes(file_row['nonce_hex'], ciphertext)
        # attempt to decode; if binary, show notice
        try:
            plaintext = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError:
            plaintext = ""
            flash("File appears to be binary or not UTF-8; editing not possible via web editor.", "warning")
            return redirect(url_for("dashboard"))
    except Exception:
        flash("Decryption failed or corrupted file", "danger")
        return redirect(url_for("dashboard"))

    return render_template("edit.html", f=file_row, content=plaintext)

# ----- Share file (owner-only) -----
@app.route("/share/<int:file_id>", methods=["GET", "POST"])
@require_login
def share_file(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if not is_owner(file_row, session['user_id']):
        abort(403)

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            flash("Provide a username to share with", "warning")
            return redirect(url_for("share_file", file_id=file_id))

        target = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not target:
            flash("User does not exist", "danger")
            return redirect(url_for("share_file", file_id=file_id))

        target_id = target['id']
        # prevent sharing with self
        if target_id == session['user_id']:
            flash("Cannot share file with yourself", "warning")
            return redirect(url_for("share_file", file_id=file_id))

        # prevent duplicate shares
        exists = db.execute("SELECT 1 FROM file_shares WHERE file_id=? AND shared_with_user=?", (file_id, target_id)).fetchone()
        if exists:
            flash("File already shared with that user", "info")
            return redirect(url_for("share_file", file_id=file_id))

        db.execute(
            "INSERT INTO file_shares (file_id, owner_id, shared_with_user, created_at) VALUES (?, ?, ?, ?)",
            (file_id, session['user_id'], target_id, datetime.datetime.utcnow().isoformat())
        )
        db.commit()
        flash(f"File shared with {username}", "success")
        return redirect(url_for("dashboard"))

    # GET -> show simple share form
    # also list current shares for this file (usernames)
    shares = db.execute("""
        SELECT u.username, s.created_at, s.id as share_id
        FROM file_shares s JOIN users u ON s.shared_with_user = u.id
        WHERE s.file_id = ?
    """, (file_id,)).fetchall()
    return render_template("share.html", f=file_row, shares=shares)

# ----- Unshare (owner-only) -----
@app.route("/unshare/<int:file_id>", methods=["POST"])
@require_login
def unshare_file(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if not is_owner(file_row, session['user_id']):
        abort(403)

    share_id = request.form.get("share_id")
    if not share_id:
        flash("No share selected", "warning")
        return redirect(url_for("share_file", file_id=file_id))
    # delete the share row if exists and owned by owner
    db.execute("DELETE FROM file_shares WHERE id = ? AND owner_id = ?", (share_id, session['user_id']))
    db.commit()
    flash("Share removed", "success")
    return redirect(url_for("share_file", file_id=file_id))

# ----- Delete -----
@app.route("/delete/<int:file_id>", methods=["POST"])
@require_login
def delete_file(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)
    if file_row['owner_id'] != session['user_id']:
        abort(403)
    # remove stored file
    folder = QUARANTINE_FOLDER if file_row['quarantined'] else UPLOAD_FOLDER
    path = os.path.join(folder, file_row['storage_name'])
    try:
        if os.path.exists(path):
            os.remove(path)
    except Exception:
        pass
    # remove shares for this file too
    db.execute("DELETE FROM file_shares WHERE file_id = ?", (file_id,))
    db.execute("DELETE FROM files WHERE id = ?", (file_id,))
    db.commit()
    flash("File deleted", "success")
    return redirect(url_for("dashboard"))

# ----- View metadata -----
@app.route("/metadata/<int:file_id>")
@require_login
def metadata(file_id):
    db = get_db()
    file_row = db.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
    if not file_row:
        abort(404)

    # allow owner and shared users to view metadata
    if not is_authorized_to_view(file_row, session['user_id']):
        abort(403)

    # fetch share info (if owner)
    shares = []
    if is_owner(file_row, session['user_id']):
        shares = db.execute("""
            SELECT u.username, s.created_at, s.id as share_id
            FROM file_shares s JOIN users u ON s.shared_with_user = u.id
            WHERE s.file_id = ?
        """, (file_id,)).fetchall()

    # show metadata including uploaded_at, size, hash, quarantined flag, owner username
    owner = db.execute("SELECT username FROM users WHERE id = ?", (file_row['owner_id'],)).fetchone()
    return render_template("metadata.html", f=file_row, shares=shares, owner=owner)

# ----- Quarantine listing (for owner only shows their quarantined) -----
@app.route("/quarantine")
@require_login
def quarantine():
    db = get_db()
    files = db.execute("SELECT * FROM files WHERE owner_id = ? AND quarantined = 1 ORDER BY uploaded_at DESC", (session['user_id'],)).fetchall()
    return render_template("quarantine.html", files=files)

# ----- Logout -----
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("index"))

# ----- Simple init route (dev) -----
@app.route("/init-db")
def initdb_route():
    with app.app_context():
        init_db()
    return "DB initialized"

# ---------- Run server ----------
if __name__ == "__main__":
    # Initialize DB inside application context to avoid context errors
    with app.app_context():
        init_db()
    app.run(debug=True)
