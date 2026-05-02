import os
import hmac
import time
import hashlib
import sqlite3
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_from_directory, send_file, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "backup.db")
MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)

# ── Download token helpers ────────────────────────────────────────────────────
_TOKEN_TTL = 3600  # seconds


def _make_sig(data: str, secret: str) -> str:
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).hexdigest()


def make_download_token(file_id: int) -> str:
    """Return a signed URL-safe token embedding file_id + user_id + expiry."""
    user_id = session.get("user_id", 0)
    expires = int(time.time()) + _TOKEN_TTL
    payload = f"{file_id}:{user_id}:{expires}"
    sig = _make_sig(payload, app.secret_key)
    return f"{payload}:{sig}"


def verify_download_token(token: str, file_id: int) -> int | None:
    """Verify token; return user_id on success or None on failure."""
    try:
        parts = token.rsplit(":", 1)
        if len(parts) != 2:
            return None
        payload, sig = parts
        if not hmac.compare_digest(sig, _make_sig(payload, app.secret_key)):
            return None
        fid_str, uid_str, exp_str = payload.split(":")
        if int(fid_str) != file_id:
            return None
        if int(time.time()) > int(exp_str):
            return None
        return int(uid_str)
    except Exception:
        return None
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-change-me")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True


@app.context_processor
def inject_helpers():
    return dict(make_download_token=make_download_token)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")
        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        pw_hash = generate_password_hash(password)
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, pw_hash, datetime.utcnow().isoformat())
                )
                conn.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already taken.", "danger")
            return render_template("register.html")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("login.html")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        files = conn.execute(
            "SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC",
            (session["user_id"],)
        ).fetchall()
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for("dashboard"))

    file = request.files["file"]
    if file.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(file.filename)
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    stored_name = f"{session['user_id']}_{timestamp}_{original_name}"
    save_path = os.path.join(UPLOAD_FOLDER, stored_name)

    file.save(save_path)
    file_size = os.path.getsize(save_path)
    sha256 = sha256_of_file(save_path)

    with get_db() as conn:
        conn.execute(
            "INSERT INTO files (user_id, original_name, stored_name, size, sha256, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (session["user_id"], original_name, stored_name, file_size, sha256, datetime.utcnow().isoformat())
        )
        conn.commit()

    flash(f'"{original_name}" uploaded successfully. SHA256: {sha256[:16]}…', "success")
    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
def download(file_id):
    token = request.args.get("token", "")
    user_id = verify_download_token(token, file_id)

    # Fall back to session if token is absent / expired
    if user_id is None:
        user_id = session.get("user_id")
    if not user_id:
        abort(403)

    with get_db() as conn:
        f = conn.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, user_id)
        ).fetchone()

    if not f:
        abort(404)

    return send_from_directory(
        UPLOAD_FOLDER,
        f["stored_name"],
        as_attachment=True,
        download_name=f["original_name"]
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    with get_db() as conn:
        f = conn.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

    if not f:
        abort(404)

    stored_path = os.path.join(UPLOAD_FOLDER, f["stored_name"])
    if os.path.exists(stored_path):
        os.remove(stored_path)

    with get_db() as conn:
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()

    flash(f'"{f["original_name"]}" deleted.', "info")
    return redirect(url_for("dashboard"))


@app.route("/verify/<int:file_id>", methods=["POST"])
@login_required
def verify(file_id):
    from flask import jsonify
    with get_db() as conn:
        f = conn.execute(
            "SELECT * FROM files WHERE id = ? AND user_id = ?",
            (file_id, session["user_id"])
        ).fetchone()

    if not f:
        return jsonify({"ok": False, "message": "File not found."}), 404

    stored_path = os.path.join(UPLOAD_FOLDER, f["stored_name"])
    if not os.path.exists(stored_path):
        return jsonify({"ok": False, "message": "File missing from disk."})

    current_hash = sha256_of_file(stored_path)
    if current_hash == f["sha256"]:
        return jsonify({"ok": True, "message": "Integrity verified — hash matches."})
    return jsonify({
        "ok": False,
        "message": f"Integrity failure! Expected {f['sha256'][:16]}… got {current_hash[:16]}…"
    })


def format_size(size_bytes):
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 ** 2:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024**2):.1f} MB"
    return f"{size_bytes / (1024**3):.1f} GB"


app.jinja_env.filters["format_size"] = format_size


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
