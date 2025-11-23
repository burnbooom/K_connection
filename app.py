# app.py
import os
import json
import tempfile
import logging
import traceback
from datetime import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, session,
    send_from_directory, flash, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- Configuration ----------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data.json")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

# Domain restriction for signups and email changes
REQUIRED_EMAIL_DOMAIN = "edu.kunskapsskolan"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change-this-secret")
app.logger.setLevel(logging.DEBUG)

# ---------- Utilities ----------
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def allowed_file(fname):
    return "." in fname and fname.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def convo_key(a, b):
    pair = sorted([a, b])
    return f"{pair[0]}__{pair[1]}"

def email_has_allowed_domain(email):
    if not email:
        return False
    # Accept forms like user@edu.kunskapsskolan or user@sub.edu.kunskapsskolan
    email = email.strip().lower()
    if "@" not in email:
        return False
    domain = email.split("@", 1)[1]
    return domain == REQUIRED_EMAIL_DOMAIN or domain.endswith("." + REQUIRED_EMAIL_DOMAIN)

# ---------- Persistence helpers (read on demand, write atomic with fallback) ----------
def read_data():
    if not os.path.exists(DATA_FILE):
        app.logger.debug("read_data: missing, returning empty structure")
        return {"users": {}, "posts": [], "messages": {}}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        app.logger.debug("read_data: read %s (users=%d posts=%d)",
                         os.path.abspath(DATA_FILE),
                         len(d.get("users", {})),
                         len(d.get("posts", [])))
        return d
    except Exception:
        app.logger.exception("read_data: failed to parse data.json; returning empty structure")
        return {"users": {}, "posts": [], "messages": {}}

def write_data_atomic(obj):
    dirpath = os.path.dirname(DATA_FILE) or "."
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="datajson_", dir=dirpath)
        app.logger.debug("write_data_atomic: tmp_path=%s", tmp_path)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, DATA_FILE)
        app.logger.info("write_data_atomic: atomic replace succeeded %s", os.path.abspath(DATA_FILE))
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                head = f.read(2048)
            app.logger.debug("write_data_atomic: head after write: %s", head[:2048])
        except Exception:
            app.logger.exception("write_data_atomic: readback failed")
        return
    except Exception:
        app.logger.exception("write_data_atomic: atomic replace failed, falling back: %s", traceback.format_exc())
        try:
            if fd:
                try:
                    os.close(fd)
                except Exception:
                    pass
            if tmp_path and os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            app.logger.exception("write_data_atomic: cleanup failed")
    # fallback direct write
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        app.logger.info("write_data_atomic: direct write succeeded %s", os.path.abspath(DATA_FILE))
    except Exception:
        app.logger.exception("write_data_atomic: direct write failed")
        raise

# ---------- Small helpers ----------
def find_user_by_email_disk(email_lower):
    d = read_data()
    for handle, rec in d.get("users", {}).items():
        e = rec.get("email")
        if e and e.lower() == email_lower:
            return handle, rec
    return None, None

def ensure_user_on_disk(handle):
    """
    Ensure a user record exists on disk. IMPORTANT: this MUST NOT modify session.
    It only creates a user record when missing and writes data.json.
    """
    if not handle:
        return
    d = read_data()
    users = d.setdefault("users", {})
    if handle not in users:
        users[handle] = {
            "handle": handle,
            "email": None,
            "password_hash": None,
            "bio": "",
            "followers": [],
            "following": [],
            "stats": {"posts": 0, "likes_received": 0},
            "created": now_str()
        }
        write_data_atomic(d)

# ---------- Routes: landing / auth ----------
@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        handle_raw = request.form.get("handle", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not handle_raw or not email or not password:
            flash("Please fill all fields", "danger")
            return redirect(url_for("signup"))
        if len(password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return redirect(url_for("signup"))

        if not email_has_allowed_domain(email):
            flash(f"Only {REQUIRED_EMAIL_DOMAIN} email addresses are allowed to sign up", "danger")
            return redirect(url_for("signup"))

        handle = handle_raw if handle_raw.startswith("@") else "@" + handle_raw

        d = read_data()
        users = d.setdefault("users", {})

        app.logger.debug("Signup attempt: handle=%r email=%r data_file=%s", handle, email, os.path.abspath(DATA_FILE))
        app.logger.debug("Existing handles: %s", list(users.keys()))

        if handle in users:
            flash("Handle already exists", "danger")
            return redirect(url_for("signup"))

        for r in users.values():
            if r.get("email") and r["email"].lower() == email:
                flash("Email already registered", "danger")
                return redirect(url_for("signup"))

        users[handle] = {
            "handle": handle,
            "email": email,
            "password_hash": generate_password_hash(password),
            "bio": "",
            "followers": [],
            "following": [],
            "stats": {"posts": 0, "likes_received": 0},
            "created": now_str()
        }

        try:
            write_data_atomic(d)
        except Exception:
            app.logger.exception("Saving new user failed")
            flash("Server error saving account", "danger")
            return redirect(url_for("signup"))

        session["user"] = handle
        flash("Account created and signed in", "success")
        return redirect(url_for("feed"))
    return render_template("signup.html", required_domain=REQUIRED_EMAIL_DOMAIN)

@app.route("/login", methods=["GET", "POST"])
def login():
    # login only writes session on successful POST with credentials
    if request.method == "POST":
        identifier = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        if not identifier or not password:
            flash("Please provide email/handle and password", "danger")
            return redirect(url_for("login"))

        ident_lower = identifier.lower()
        handle, record = find_user_by_email_disk(ident_lower)
        if not record:
            lookup_handle = identifier if identifier.startswith("@") else "@" + identifier
            d = read_data()
            rec = d.get("users", {}).get(lookup_handle)
            if rec:
                handle, record = lookup_handle, rec

        if not record:
            app.logger.debug("Login failed: no record for identifier=%r", identifier)
            flash("No account found. Please sign up.", "danger")
            return redirect(url_for("login"))

        stored_hash = record.get("password_hash")
        if not stored_hash:
            flash("This account has no password set. Please reset your password or sign up again.", "danger")
            return redirect(url_for("login"))

        try:
            ok = check_password_hash(stored_hash, password)
        except Exception:
            app.logger.exception("check_password_hash raised")
            ok = False

        if not ok:
            app.logger.debug("Login failed: incorrect password for handle=%s", handle)
            flash("Incorrect password", "danger")
            return redirect(url_for("login"))

        session["user"] = handle
        flash("Signed in", "success")
        return redirect(url_for("feed"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------- Forgot placeholder ----------
@app.route("/forgot", methods=["GET"])
def forgot():
    return render_template("forgot.html")

@app.route("/forgot", methods=["POST"])
def forgot_post():
    email = request.form.get("email", "").strip().lower()
    if not email:
        flash("Please enter your email address", "danger")
        return redirect(url_for("forgot"))
    flash("If an account exists for that email, a reset link will be sent", "info")
    return redirect(url_for("login"))

# ---------- Feed (following or global toggle) ----------
@app.route("/feed", methods=["GET", "POST"])
def feed():
    user = session.get("user")
    if user is None:
        return redirect(url_for("index"))

    # POST: create a new post
    if request.method == "POST":
        text = request.form.get("text", "").strip()
        image_file = request.files.get("image")
        image_name = None
        if image_file and image_file.filename and allowed_file(image_file.filename):
            fname = secure_filename(image_file.filename)
            ts = datetime.now().strftime("%Y%m%d%H%M%S")
            fname = f"{ts}_{fname}"
            path = os.path.join(UPLOAD_FOLDER, fname)
            image_file.save(path)
            image_name = fname

        if text or image_name:
            d = read_data()
            d.setdefault("posts", [])
            post = {
                "user": user,
                "text": text,
                "image": image_name,
                "time": now_str(),
                "likes": 0,
                "liked_by": [],
                "comments": []
            }
            d["posts"].insert(0, post)
            d.setdefault("users", {}).setdefault(user, {"stats": {"posts": 0}})["stats"]["posts"] = \
                d["users"][user]["stats"].get("posts", 0) + 1
            write_data_atomic(d)
        return redirect(url_for("feed"))

    # GET: choose feed mode (following or global)
    d = read_data()
    posts_all = d.get("posts", [])

    show_global = request.args.get("global") == "1"
    if show_global:
        posts = posts_all
    else:
        users = d.get("users", {})
        my_following = set(users.get(user, {}).get("following", []))
        my_following.add(user)
        posts = [p for p in posts_all if p.get("user") in my_following]

    # build recent chats for sidebar
    recent_chats = []
    messages = d.get("messages", {})
    for key, msgs in messages.items():
        if not msgs:
            continue
        participants = key.split("__")
        if user not in participants:
            continue
        other = participants[0] if participants[1] == user else participants[1]
        last = msgs[-1]
        last_time = last.get("time") or ""
        preview = (last.get("text") or "")[:80]
        recent_chats.append({"user": other, "last_time": last_time, "preview": preview})
    recent_chats.sort(key=lambda x: x.get("last_time") or "", reverse=True)

    users = d.get("users", {})
    following = list(set(users.get(user, {}).get("following", [])) - {user})
    return render_template("feed.html", posts=posts, following=following, recent_chats=recent_chats, show_global=show_global)

# ---------- Post interactions ----------
@app.route("/like/<int:post_id>", methods=["POST"])
def like_post(post_id):
    user = session.get("user")
    if user is None:
        return redirect(url_for("index"))
    d = read_data()
    posts = d.get("posts", [])
    if 0 <= post_id < len(posts):
        if user not in posts[post_id].get("liked_by", []):
            posts[post_id].setdefault("liked_by", []).append(user)
            posts[post_id]["likes"] = posts[post_id].get("likes", 0) + 1
            poster = posts[post_id]["user"]
            d.setdefault("users", {}).setdefault(poster, {"stats": {"posts": 0}})["stats"]["likes_received"] = \
                d["users"][poster]["stats"].get("likes_received", 0) + 1
            write_data_atomic(d)
    return redirect(url_for("feed"))

@app.route("/comment/<int:post_id>", methods=["POST"])
def comment_post(post_id):
    user = session.get("user")
    if user is None:
        return redirect(url_for("index"))
    c = request.form.get("comment", "").strip()
    if not c:
        return redirect(url_for("feed"))
    d = read_data()
    posts = d.get("posts", [])
    if 0 <= post_id < len(posts):
        posts[post_id].setdefault("comments", []).append(f"{user}: {c}")
        write_data_atomic(d)
    return redirect(url_for("feed"))

@app.route("/share/<int:post_id>", methods=["POST"])
def share_post(post_id):
    user = session.get("user")
    if user is None:
        return redirect(url_for("index"))
    d = read_data()
    posts = d.get("posts", [])
    if 0 <= post_id < len(posts):
        src = posts[post_id]
        new_post = {
            "user": user,
            "text": f"Shared from {src['user']}: {src.get('text','')}",
            "image": src.get("image"),
            "time": now_str(),
            "likes": 0,
            "liked_by": [],
            "comments": []
        }
        d.setdefault("posts", []).insert(0, new_post)
        d.setdefault("users", {}).setdefault(user, {"stats": {"posts": 0}})["stats"]["posts"] += 1
        write_data_atomic(d)
    return redirect(url_for("feed"))

# ---------- Profile (safe: does NOT set session) ----------
@app.route("/profile/<user>")
def profile(user):
    # do NOT assign session["user"] here
    ensure_user_on_disk(user)
    d = read_data()
    user_posts = [p for p in d.get("posts", []) if p.get("user") == user]
    user_record = d.get("users", {}).get(user, {})
    return render_template("profile.html", user=user, posts=user_posts, record=user_record)

# ---------- Profile edit ----------
@app.route("/profile/edit", methods=["GET"])
def edit_profile():
    me = session.get("user")
    if me is None:
        flash("You must be signed in to edit your profile", "danger")
        return redirect(url_for("login"))
    d = read_data()
    record = d.get("users", {}).get(me, {})
    return render_template("edit_profile.html", user=me, record=record, required_domain=REQUIRED_EMAIL_DOMAIN)

@app.route("/profile/edit", methods=["POST"])
def edit_profile_post():
    me = session.get("user")
    if me is None:
        flash("You must be signed in to edit your profile", "danger")
        return redirect(url_for("login"))

    new_email = request.form.get("email", "").strip()
    new_bio = request.form.get("bio", "").strip()
    new_password = request.form.get("password", "")
    confirm_password = request.form.get("password_confirm", "")

    if new_password and new_password != confirm_password:
        flash("Passwords do not match", "danger")
        return redirect(url_for("edit_profile"))
    if new_password and len(new_password) < 6:
        flash("Password must be at least 6 characters", "danger")
        return redirect(url_for("edit_profile"))

    try:
        d = read_data()
        users = d.setdefault("users", {})
        if me not in users:
            flash("User record not found", "danger")
            return redirect(url_for("index"))

        # If an email is provided, enforce the required domain
        if new_email:
            if not email_has_allowed_domain(new_email):
                flash(f"Email must be within the {REQUIRED_EMAIL_DOMAIN} domain", "danger")
                return redirect(url_for("edit_profile"))
            new_email_lower = new_email.lower()
            for handle, rec in users.items():
                if handle == me:
                    continue
                e = rec.get("email")
                if e and e.lower() == new_email_lower:
                    flash("That email is already used by another account", "danger")
                    return redirect(url_for("edit_profile"))
            users[me]["email"] = new_email_lower
        else:
            users[me]["email"] = None

        users[me]["bio"] = new_bio

        if new_password:
            users[me]["password_hash"] = generate_password_hash(new_password)

        write_data_atomic(d)
        flash("Profile updated", "success")
    except Exception:
        app.logger.exception("Failed to update profile")
        flash("Server error saving profile", "danger")
        return redirect(url_for("edit_profile"))

    return redirect(url_for("profile", user=me))

# ---------- Follow / Unfollow ----------
@app.route("/follow/<user>", methods=["POST"])
def follow(user):
    me = session.get("user")
    if me is None:
        return redirect(url_for("index"))
    d = read_data()
    d.setdefault("users", {})
    d["users"].setdefault(me, {"followers": [], "following": [], "stats": {"posts": 0}})
    d["users"].setdefault(user, {"followers": [], "following": [], "stats": {"posts": 0}})
    if user not in d["users"][me].get("following", []):
        d["users"][me].setdefault("following", []).append(user)
        d["users"][user].setdefault("followers", []).append(me)
        write_data_atomic(d)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ('', 200)
    return redirect(url_for("profile", user=user))

@app.route("/unfollow/<user>", methods=["POST"])
def unfollow(user):
    me = session.get("user")
    if me is None:
        return redirect(url_for("index"))
    d = read_data()
    if me in d.get("users", {}) and user in d["users"]:
        if user in d["users"][me].get("following", []):
            d["users"][me]["following"].remove(user)
        if me in d["users"][user].get("followers", []):
            d["users"][user]["followers"].remove(me)
        write_data_atomic(d)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ('', 200)
    return redirect(url_for("profile", user=user))

# ---------- Chat ----------
@app.route("/chat/<user>", methods=["GET"])
def chat(user):
    current = session.get("user")
    if current is None:
        return redirect(url_for("index"))
    ensure_user_on_disk(user)
    d = read_data()
    key = convo_key(current, user)
    msgs = d.setdefault("messages", {}).setdefault(key, [])
    # also build recent_chats for left panel
    recent_chats = []
    for key2, msgs2 in d.get("messages", {}).items():
        if not msgs2:
            continue
        parts = key2.split("__")
        if current not in parts:
            continue
        other = parts[0] if parts[1] == current else parts[1]
        last = msgs2[-1]
        recent_chats.append({"user": other, "last_time": last.get("time",""), "preview": (last.get("text") or "")[:80]})
    recent_chats.sort(key=lambda x: x.get("last_time") or "", reverse=True)
    return render_template("chat.html", user=user, messages=msgs, recent_chats=recent_chats)

@app.route("/send_message", methods=["POST"])
def send_message():
    sender = session.get("user")
    if sender is None:
        return redirect(url_for("index"))
    to_user = request.form.get("to", "").strip()
    text = request.form.get("text", "").strip()
    if not to_user or not text:
        return redirect(url_for("chat", user=to_user or sender))
    ensure_user_on_disk(to_user)
    d = read_data()
    key = convo_key(sender, to_user)
    msg = {"sender": sender, "recipient": to_user, "text": text, "time": now_str()}
    d.setdefault("messages", {}).setdefault(key, []).append(msg)
    write_data_atomic(d)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return ('', 200)
    return redirect(url_for("chat", user=to_user))

# ---------- Static uploads ----------
@app.route("/static/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

# ---------- Debug endpoints ----------
@app.route("/_debug/data", methods=["GET"])
def _debug_data():
    d = read_data()
    return jsonify({
        "data_file_abs": os.path.abspath(DATA_FILE),
        "exists_on_disk": os.path.exists(DATA_FILE),
        "users": list(d.get("users", {}).keys()),
        "posts": len(d.get("posts", [])),
        "messages_keys": list(d.get("messages", {}).keys())[:20]
    })

@app.route("/_debug/reset_data", methods=["POST"])
def _debug_reset_data():
    try:
        backup = DATA_FILE + ".bak"
        if os.path.exists(DATA_FILE):
            os.replace(DATA_FILE, backup)
            app.logger.info("Backed up data.json -> %s", backup)
        fresh = {"users": {}, "posts": [], "messages": {}}
        write_data_atomic(fresh)
        return "reset", 200
    except Exception as e:
        app.logger.exception("Reset failed")
        return f"error: {e}", 500

@app.route("/_debug/add_test_user", methods=["POST"])
def _debug_add_test_user():
    try:
        d = read_data()
        handle = "@test" + datetime.now().strftime("%H%M%S")
        d.setdefault("users", {})[handle] = {
            "handle": handle,
            "email": f"{handle[1:]}@{REQUIRED_EMAIL_DOMAIN}",
            "password_hash": generate_password_hash("password123"),
            "bio": "",
            "followers": [],
            "following": [],
            "stats": {"posts": 0, "likes_received": 0},
            "created": now_str()
        }
        write_data_atomic(d)
        return jsonify({"created": handle}), 201
    except Exception:
        app.logger.exception("Failed to add test user")
        return "error", 500

# ---------- Bootstrap (optional) ----------
def bootstrap_if_requested():
    if os.environ.get("BOOTSTRAP_DEMO") != "1":
        return
    d = read_data()
    if not d.get("users"):
        for h in ["@alice", "@bob", "@charlie", "@david"]:
            d.setdefault("users", {})[h] = {
                "handle": h,
                "email": f"{h[1:]}@{REQUIRED_EMAIL_DOMAIN}",
                "password_hash": generate_password_hash("password123"),
                "bio": "",
                "followers": [],
                "following": [],
                "stats": {"posts": 0, "likes_received": 0},
                "created": now_str()
            }
        d["posts"] = [
            {"user": "@alice", "text": "Hello world!", "image": None, "time": now_str(),
             "likes": 2, "liked_by": ["@bob", "@charlie"], "comments": ["@bob: Nice!", "@charlie: 👋"]},
        ]
        write_data_atomic(d)
        app.logger.info("Bootstrap demo data created")

if __name__ == "__main__":
    bootstrap_if_requested()
    app.run(host="0.0.0.0", port=8080, debug=False)
