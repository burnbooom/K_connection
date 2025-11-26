# app.py
"""
Robust Flask app with SQLite backend.
This version addresses the "My profile" redirect issue and includes:
- Normalized session["user"] (always starts with @)
- /profile redirect to signed-in user's profile
- Defensive /profile/<user> route that never silently redirects to feed
- Signup/login that set and log session user
- Feed, posts, likes, comments, share, follow/unfollow, chat
- Debug endpoints for inspection and reset (remove in production)
- SQLite DB at data/app.db (data/ folder created automatically)
Notes:
- Set FLASK_SECRET in environment for production sessions.
- On ephemeral hosts (Render), attach persistent storage or use a managed DB.
"""

import os
import json
import sqlite3
from datetime import datetime
from functools import wraps
from flask import (
    Flask, g, render_template, request, redirect, url_for, session,
    send_from_directory, flash, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- Configuration ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
REQUIRED_EMAIL_DOMAIN = "edu.kunskapsskolan.se"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SECRET_KEY = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# ---------------- App setup ----------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(
    SECRET_KEY=SECRET_KEY,
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,  # 8 MB
)
app.logger.setLevel("DEBUG")

# ---------------- Database helpers ----------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        db.row_factory = sqlite3.Row
        g._db = db
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()
        g._db = None

def init_db():
    db = get_db()
    cur = db.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      handle TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE,
      password_hash TEXT,
      bio TEXT DEFAULT '',
      created_at TEXT NOT NULL,
      stats_posts INTEGER DEFAULT 0,
      stats_likes_received INTEGER DEFAULT 0
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_handle TEXT NOT NULL,
      text TEXT,
      image TEXT,
      time TEXT NOT NULL,
      likes INTEGER DEFAULT 0,
      liked_by TEXT DEFAULT '[]',
      comments TEXT DEFAULT '[]'
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      convo_key TEXT NOT NULL,
      sender TEXT NOT NULL,
      recipient TEXT NOT NULL,
      text TEXT,
      time TEXT NOT NULL
    );
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS follows (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      follower TEXT NOT NULL,
      following TEXT NOT NULL,
      UNIQUE(follower, following)
    );
    """)
    db.commit()

with app.app_context():
    init_db()

# ---------------- Utilities ----------------
def now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def allowed_file(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def convo_key(a, b):
    pair = sorted([a, b])
    return f"{pair[0]}__{pair[1]}"

def normalize_handle(h):
    if not h:
        return None
    h = str(h).strip()
    return h if h.startswith("@") else "@" + h

def email_has_allowed_domain(email):
    if not email:
        return False
    email = email.strip().lower()
    if "@" not in email:
        return False
    domain = email.split("@", 1)[1]
    return domain == REQUIRED_EMAIL_DOMAIN or domain.endswith("." + REQUIRED_EMAIL_DOMAIN)

def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            flash("Please sign in to continue", "danger")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped

# ---------------- User helpers ----------------
def ensure_user_exists(handle):
    if not handle:
        return
    handle = normalize_handle(handle)
    db = get_db()
    cur = db.execute("SELECT id FROM users WHERE handle = ?", (handle,))
    if cur.fetchone():
        return
    now = now_str()
    db.execute("INSERT INTO users (handle, created_at, bio) VALUES (?, ?, ?)", (handle, now, ""))
    db.commit()
    app.logger.debug("Created minimal user record for %s", handle)

def find_user_by_email(email_lower):
    db = get_db()
    cur = db.execute("SELECT handle, email, password_hash, bio FROM users WHERE lower(email) = ?", (email_lower,))
    return cur.fetchone()

# ---------------- Routes: auth & landing ----------------
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        handle_raw = (request.form.get("handle") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not handle_raw or not email or not password:
            flash("Please fill all fields", "danger")
            return redirect(url_for("signup"))
        if len(password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return redirect(url_for("signup"))
        if not email_has_allowed_domain(email):
            flash(f"Only {REQUIRED_EMAIL_DOMAIN} email addresses are allowed", "danger")
            return redirect(url_for("signup"))

        handle = normalize_handle(handle_raw)

        db = get_db()
        cur = db.execute("SELECT id FROM users WHERE handle = ?", (handle,))
        if cur.fetchone():
            flash("Handle already exists", "danger")
            return redirect(url_for("signup"))
        cur = db.execute("SELECT id FROM users WHERE lower(email) = ?", (email.lower(),))
        if cur.fetchone():
            flash("Email already registered", "danger")
            return redirect(url_for("signup"))

        pw_hash = generate_password_hash(password)
        now = now_str()
        db.execute(
            "INSERT INTO users (handle, email, password_hash, bio, created_at) VALUES (?, ?, ?, ?, ?)",
            (handle, email, pw_hash, "", now)
        )
        db.commit()

        # normalize and set session user
        session["user"] = normalize_handle(handle)
        app.logger.debug("session['user'] set to: %r (signup)", session.get("user"))
        flash("Account created and signed in", "success")
        return redirect(url_for("feed"))
    return render_template("signup.html", required_domain=REQUIRED_EMAIL_DOMAIN)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        if not identifier or not password:
            flash("Please provide email/handle and password", "danger")
            return redirect(url_for("login"))

        db = get_db()
        row = None
        if "@" in identifier:
            row = find_user_by_email(identifier.lower())
        if not row:
            lookup_handle = identifier if identifier.startswith("@") else "@" + identifier
            cur = db.execute("SELECT handle, email, password_hash FROM users WHERE handle = ?", (lookup_handle,))
            row = cur.fetchone()

        if not row:
            flash("No account found. Please sign up.", "danger")
            return redirect(url_for("signup"))

        stored_hash = row["password_hash"]
        if not stored_hash:
            flash("This account has no password set. Please reset or sign up again.", "danger")
            return redirect(url_for("login"))

        try:
            ok = check_password_hash(stored_hash, password)
        except Exception:
            ok = False

        if not ok:
            flash("Incorrect password", "danger")
            return redirect(url_for("login"))

        # set normalized session user
        handle = normalize_handle(row["handle"])
        session["user"] = handle
        app.logger.debug("session['user'] set to: %r (login)", session.get("user"))
        flash("Signed in", "success")
        return redirect(url_for("feed"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Signed out", "info")
    return redirect(url_for("index"))

# ---------------- Forgot placeholder ----------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        flash("If an account exists for that email, a reset link will be sent", "info")
        return redirect(url_for("login"))
    return render_template("forgot.html")

# ---------------- Profile redirect for /profile ----------------
@app.route("/profile")
@login_required
def my_profile():
    user = session.get("user")
    if not user:
        return redirect(url_for("index"))
    user = normalize_handle(user)
    return redirect(url_for("profile", user=user))

# ---------------- Feed and posts ----------------
@app.route("/feed", methods=["GET", "POST"])
@login_required
def feed():
    me = session.get("user")
    db = get_db()

    if request.method == "POST":
        text = (request.form.get("text") or "").strip()
        image_file = request.files.get("image")
        image_name = None
        if image_file and image_file.filename and allowed_file(image_file.filename):
            fname = secure_filename(image_file.filename)
            ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
            fname = f"{ts}_{fname}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], fname)
            image_file.save(path)
            image_name = fname

        if text or image_name:
            now = now_str()
            db.execute(
                "INSERT INTO posts (user_handle, text, image, time, likes, liked_by, comments) VALUES (?, ?, ?, ?, 0, ?, ?)",
                (me, text, image_name, now, json.dumps([]), json.dumps([]))
            )
            db.execute("UPDATE users SET stats_posts = stats_posts + 1 WHERE handle = ?", (me,))
            db.commit()
        return redirect(url_for("feed"))

    show_global = request.args.get("global") == "1"
    posts = []
    cur = db.execute("SELECT * FROM posts ORDER BY id DESC")
    rows = cur.fetchall()
    if show_global:
        rows_to_show = rows
    else:
        following_rows = db.execute("SELECT following FROM follows WHERE follower = ?", (me,)).fetchall()
        following = {r["following"] for r in following_rows}
        following.add(me)
        rows_to_show = [r for r in rows if r["user_handle"] in following]

    for r in rows_to_show:
        posts.append({
            "id": r["id"],
            "user": r["user_handle"],
            "text": r["text"],
            "image": r["image"],
            "time": r["time"],
            "likes": r["likes"],
            "liked_by": json.loads(r["liked_by"] or "[]"),
            "comments": json.loads(r["comments"] or "[]")
        })

    recent_chats = []
    cur = db.execute("SELECT convo_key, sender, recipient, text, time FROM messages ORDER BY id DESC")
    seen = set()
    for r in cur.fetchall():
        key = r["convo_key"]
        if key in seen:
            continue
        seen.add(key)
        parts = key.split("__")
        if me not in parts:
            continue
        other = parts[0] if parts[1] == me else parts[1]
        recent_chats.append({"user": other, "last_time": r["time"], "preview": (r["text"] or "")[:80]})
    recent_chats = sorted(recent_chats, key=lambda x: x.get("last_time") or "", reverse=True)

    following = [r["following"] for r in db.execute("SELECT following FROM follows WHERE follower = ?", (me,)).fetchall()]

    return render_template("feed.html", posts=posts, following=following, recent_chats=recent_chats, show_global=show_global)

# ---------------- Post interactions ----------------
@app.route("/like/<int:post_id>", methods=["POST"])
@login_required
def like_post(post_id):
    me = session.get("user")
    db = get_db()
    cur = db.execute("SELECT liked_by, likes, user_handle FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return redirect(url_for("feed"))
    liked_by = json.loads(row["liked_by"] or "[]")
    if me not in liked_by:
        liked_by.append(me)
        likes = (row["likes"] or 0) + 1
        db.execute("UPDATE posts SET liked_by = ?, likes = ? WHERE id = ?", (json.dumps(liked_by), likes, post_id))
        db.execute("UPDATE users SET stats_likes_received = stats_likes_received + 1 WHERE handle = ?", (row["user_handle"],))
        db.commit()
    return redirect(url_for("feed"))

@app.route("/comment/<int:post_id>", methods=["POST"])
@login_required
def comment_post(post_id):
    me = session.get("user")
    comment = (request.form.get("comment") or "").strip()
    if not comment:
        return redirect(url_for("feed"))
    db = get_db()
    cur = db.execute("SELECT comments FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return redirect(url_for("feed"))
    comments = json.loads(row["comments"] or "[]")
    comments.append(f"{me}: {comment}")
    db.execute("UPDATE posts SET comments = ? WHERE id = ?", (json.dumps(comments), post_id))
    db.commit()
    return redirect(url_for("feed"))

@app.route("/share/<int:post_id>", methods=["POST"])
@login_required
def share_post(post_id):
    me = session.get("user")
    db = get_db()
    cur = db.execute("SELECT user_handle, text, image FROM posts WHERE id = ?", (post_id,))
    row = cur.fetchone()
    if not row:
        return redirect(url_for("feed"))
    new_text = f"Shared from {row['user_handle']}: {row['text'] or ''}"
    now = now_str()
    db.execute(
        "INSERT INTO posts (user_handle, text, image, time, likes, liked_by, comments) VALUES (?, ?, ?, ?, 0, ?, ?)",
        (me, new_text, row["image"], now, json.dumps([]), json.dumps([]))
    )
    db.execute("UPDATE users SET stats_posts = stats_posts + 1 WHERE handle = ?", (me,))
    db.commit()
    return redirect(url_for("feed"))

# ---------------- Profile ----------------
@app.route("/profile/<user>")
def profile(user):
    try:
        if not user:
            flash("Invalid profile requested", "danger")
            return redirect(url_for("feed"))

        user = normalize_handle(user)
        ensure_user_exists(user)
        db = get_db()

        cur = db.execute("SELECT * FROM posts WHERE user_handle = ? ORDER BY id DESC", (user,))
        posts = []
        for r in cur.fetchall():
            posts.append({
                "id": r["id"],
                "user": r["user_handle"],
                "text": r["text"],
                "image": r["image"],
                "time": r["time"],
                "likes": r["likes"],
                "liked_by": json.loads(r["liked_by"] or "[]"),
                "comments": json.loads(r["comments"] or "[]")
            })

        cur = db.execute(
            "SELECT handle, email, bio, created_at, stats_posts, stats_likes_received FROM users WHERE handle = ?",
            (user,)
        )
        row = cur.fetchone()
        if row is None:
            now = now_str()
            db.execute("INSERT INTO users (handle, created_at, bio) VALUES (?, ?, ?)", (user, now, ""))
            db.commit()
            record = {"handle": user, "email": None, "bio": "", "created_at": now, "stats_posts": 0, "stats_likes_received": 0}
        else:
            record = {
                "handle": row["handle"],
                "email": row["email"],
                "bio": row["bio"],
                "created_at": row["created_at"],
                "stats_posts": row["stats_posts"],
                "stats_likes_received": row["stats_likes_received"]
            }

        return render_template("profile.html", user=user, posts=posts, record=record)
    except Exception as exc:
        app.logger.exception("Error rendering profile for %s: %s", user, exc)
        flash("Sorry — something went wrong loading that profile. The error has been logged.", "danger")
        return redirect(url_for("feed"))

# ---------------- Profile edit ----------------
@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    me = session.get("user")
    db = get_db()
    if request.method == "POST":
        new_email = (request.form.get("email") or "").strip()
        new_bio = (request.form.get("bio") or "").strip()
        new_password = request.form.get("password") or ""
        confirm_password = request.form.get("password_confirm") or ""

        if new_password and new_password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for("edit_profile"))
        if new_password and len(new_password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return redirect(url_for("edit_profile"))

        if new_email:
            if not email_has_allowed_domain(new_email):
                flash(f"Email must be within the {REQUIRED_EMAIL_DOMAIN} domain", "danger")
                return redirect(url_for("edit_profile"))
            cur = db.execute("SELECT handle FROM users WHERE lower(email) = ? AND handle != ?", (new_email.lower(), me))
            if cur.fetchone():
                flash("That email is already used by another account", "danger")
                return redirect(url_for("edit_profile"))
            db.execute("UPDATE users SET email = ? WHERE handle = ?", (new_email.lower(), me))
        else:
            db.execute("UPDATE users SET email = NULL WHERE handle = ?", (me,))

        db.execute("UPDATE users SET bio = ? WHERE handle = ?", (new_bio, me))
        if new_password:
            db.execute("UPDATE users SET password_hash = ? WHERE handle = ?", (generate_password_hash(new_password), me))
        db.commit()
        flash("Profile updated", "success")
        return redirect(url_for("profile", user=me))

    cur = db.execute("SELECT email, bio FROM users WHERE handle = ?", (me,))
    record = cur.fetchone()
    return render_template("edit_profile.html", user=me, record=record, required_domain=REQUIRED_EMAIL_DOMAIN)

# ---------------- Follow / Unfollow ----------------
@app.route("/follow/<user>", methods=["POST"])
@login_required
def follow(user):
    me = session.get("user")
    db = get_db()
    try:
        db.execute("INSERT OR IGNORE INTO follows (follower, following) VALUES (?, ?)", (me, user))
        db.commit()
    except Exception:
        app.logger.exception("Follow failed")
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ('', 200)
    return redirect(url_for("profile", user=user))

@app.route("/unfollow/<user>", methods=["POST"])
@login_required
def unfollow(user):
    me = session.get("user")
    db = get_db()
    db.execute("DELETE FROM follows WHERE follower = ? AND following = ?", (me, user))
    db.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ('', 200)
    return redirect(url_for("profile", user=user))

# ---------------- Chat ----------------
@app.route("/chat/<user>", methods=["GET"])
@login_required
def chat(user):
    me = session.get("user")
    ensure_user_exists(user)
    db = get_db()
    key = convo_key(me, user)
    cur = db.execute("SELECT sender, recipient, text, time FROM messages WHERE convo_key = ? ORDER BY id ASC", (key,))
    msgs = [dict(r) for r in cur.fetchall()]
    recent_chats = []
    cur = db.execute("SELECT convo_key, sender, recipient, text, time FROM messages ORDER BY id DESC")
    seen = set()
    for r in cur.fetchall():
        k = r["convo_key"]
        if k in seen:
            continue
        seen.add(k)
        parts = k.split("__")
        if me not in parts:
            continue
        other = parts[0] if parts[1] == me else parts[1]
        recent_chats.append({"user": other, "last_time": r["time"], "preview": (r["text"] or "")[:80]})
    recent_chats = sorted(recent_chats, key=lambda x: x.get("last_time") or "", reverse=True)
    return render_template("chat.html", user=user, messages=msgs, recent_chats=recent_chats)

@app.route("/send_message", methods=["POST"])
@login_required
def send_message():
    sender = session.get("user")
    to_user = (request.form.get("to") or "").strip()
    text = (request.form.get("text") or "").strip()
    if not to_user or not text:
        return redirect(url_for("chat", user=to_user or sender))
    ensure_user_exists(to_user)
    db = get_db()
    key = convo_key(sender, to_user)
    now = now_str()
    db.execute(
        "INSERT INTO messages (convo_key, sender, recipient, text, time) VALUES (?, ?, ?, ?, ?)",
        (key, sender, to_user, text, now)
    )
    db.commit()
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ('', 200)
    return redirect(url_for("chat", user=to_user))

# ---------------- Uploads ----------------
@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# ---------------- Debug endpoints ----------------
@app.route("/_debug/data", methods=["GET"])
def _debug_data():
    db = get_db()
    users = [r["handle"] for r in db.execute("SELECT handle FROM users").fetchall()]
    posts_count = db.execute("SELECT COUNT(*) as c FROM posts").fetchone()["c"]
    messages_keys = [r["convo_key"] for r in db.execute("SELECT DISTINCT convo_key FROM messages ORDER BY id DESC LIMIT 20").fetchall()]
    return jsonify({
        "db_path": os.path.abspath(DB_PATH),
        "exists_on_disk": os.path.exists(DB_PATH),
        "users": users,
        "posts": posts_count,
        "messages_keys": messages_keys
    })

@app.route("/_debug/reset_data", methods=["POST"])
def _debug_reset_data():
    try:
        if os.path.exists(DB_PATH):
            backup = DB_PATH + ".bak"
            os.replace(DB_PATH, backup)
            app.logger.info("Backed up DB to %s", backup)
        with app.app_context():
            init_db()
        return "reset", 200
    except Exception as e:
        app.logger.exception("Reset failed")
        return f"error: {e}", 500

@app.route("/_debug/add_test_user", methods=["POST"])
def _debug_add_test_user():
    try:
        db = get_db()
        handle = "@test" + datetime.utcnow().strftime("%H%M%S")
        email = f"{handle[1:]}@{REQUIRED_EMAIL_DOMAIN}"
        pw = generate_password_hash("password123")
        now = now_str()
        db.execute(
            "INSERT INTO users (handle, email, password_hash, bio, created_at) VALUES (?, ?, ?, ?, ?)",
            (handle, email, pw, "", now)
        )
        db.commit()
        return jsonify({"created": handle}), 201
    except Exception:
        app.logger.exception("Failed to add test user")
        return "error", 500

# ---------------- Bootstrap demo data ----------------
def bootstrap_if_requested():
    if os.environ.get("BOOTSTRAP_DEMO") != "1":
        return
    db = get_db()
    cur = db.execute("SELECT COUNT(*) as c FROM users")
    if cur.fetchone()["c"] > 0:
        return
    now = now_str()
    for h in ["@alice", "@bob", "@charlie", "@david"]:
        db.execute("INSERT INTO users (handle, email, password_hash, bio, created_at) VALUES (?, ?, ?, ?, ?)",
                   (h, f"{h[1:]}@{REQUIRED_EMAIL_DOMAIN}", generate_password_hash("password123"), "", now))
    db.execute(
        "INSERT INTO posts (user_handle, text, image, time, likes, liked_by, comments) VALUES (?, ?, ?, ?, 2, ?, ?)",
        ("@alice", "Hello world!", None, now, json.dumps(["@bob", "@charlie"]), json.dumps(["@bob: Nice!", "@charlie: 👋"]))
    )
    db.commit()
    app.logger.info("Bootstrap demo data created")

# ---------------- Run server ----------------
if __name__ == "__main__":
    bootstrap_if_requested()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
