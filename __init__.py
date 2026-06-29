"""
CTFd LDAP Authentication Plugin — KMITL Edition
=================================================
Authenticates students via KMITL's LDAP server using the direct-bind pattern:

  DN: uid={studentid},ou=Student,ou={faculty},ou=bkk,dc=kmitl,dc=ac,dc=th

The faculty OU is derived automatically from digits 3–4 of the student ID:
  01→eng  02→arch  03→ietech  04→agri  05→sci  07→it
  08→agro  11→fam  12→la  13→iaai  14→md  15→ami  16→nano

Accepted login formats:
  - 8-digit ID only:        69010001
  - Email format:           69010001@kmitl.ac.th

Requirements:
  pip install ldap3

Installation:
  1. Copy this folder to CTFd/plugins/CTFd-LDAP/
  2. Restart CTFd  (no further config needed for KMITL defaults)
"""

import os
import re
import logging

from flask import (
    Blueprint, render_template_string, request,
    redirect, url_for, flash, session
)
from ldap3 import Server, Connection, SIMPLE, AUTO_BIND_NO_TLS, Tls, ALL, SUBTREE
from ldap3.core.exceptions import LDAPBindError, LDAPException, LDAPSocketOpenError

from CTFd.models import Users, db
from CTFd.utils import get_config
from CTFd.utils.decorators import admins_only
from CTFd.utils.logging import log
from CTFd.utils.security.auth import login_user

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# KMITL LDAP configuration
# ---------------------------------------------------------------------------
LDAP_CONFIG = {
    "SERVER_HOST": os.environ.get("LDAP_SERVER_HOST", "10.252.92.100"),
    "SERVER_PORT": int(os.environ.get("LDAP_SERVER_PORT", 389)),
    "USE_SSL":     os.environ.get("LDAP_USE_SSL", "false").lower() == "true",
    "USE_TLS":     os.environ.get("LDAP_USE_TLS", "false").lower() == "true",
    "TIMEOUT":     int(os.environ.get("LDAP_TIMEOUT", 5)),
    "BASE_DN":     "dc=kmitl,dc=ac,dc=th",
    # Allow CTFd admin accounts to log in with their local password
    "ALLOW_LOCAL_ADMIN": os.environ.get("LDAP_ALLOW_LOCAL_ADMIN", "true").lower() == "true",
    # Auto-create CTFd account on first successful LDAP login
    "AUTO_PROVISION": os.environ.get("LDAP_AUTO_PROVISION", "true").lower() == "true",
    "KMITL_DEVELOPER_KEY": os.environ.get("KMITL_DEVELOPER_KEY", None),
    "KMITL_DEVELOPER_API": os.environ.get("KMITL_DEVELOPER_API", "https://api.kmitl.ac.th/student-catalog/v1"),
}

# ---------------------------------------------------------------------------
# Faculty code → LDAP OU mapping  (digits 3–4 of student ID, zero-padded)
# ---------------------------------------------------------------------------
FACULTY_MAP = {
    "01": "eng",
    "02": "arch",
    "03": "ietech",
    "04": "agri",
    "05": "sci",
    "07": "it",
    "08": "agro",
    "11": "fam",
    "12": "la",
    "13": "iaai",
    "14": "md",
    "15": "ami",
    "16": "nano",
}


# ---------------------------------------------------------------------------
# Get student curriculum name from KMITL catalog API
# ---------------------------------------------------------------------------

def get_student_curriculum(student_id: str):
    """
    Fetch the student's curriculum name from KMITL's catalog API.
    Returns a string like "Bachelor of Engineering Program in Food Engineering"
    or None if not found / error.
    """
    import requests

    api_url = LDAP_CONFIG["KMITL_DEVELOPER_API"]
    api_key = LDAP_CONFIG["KMITL_DEVELOPER_KEY"]

    if not api_key:
        logger.warning("KMITL LDAP: No developer API key set; cannot fetch curriculum.")
        return None

    try:
        response = requests.get(
            f"{api_url}/students/{student_id}",
            headers={"apikey": f"{api_key}"},
            timeout=5,
        )
        response.raise_for_status()
        data = response.json()
        curriculum_name = data.get("curriculum_name_en")
        return curriculum_name
    except Exception as exc:
        logger.error("KMITL LDAP: Error fetching curriculum for %s: %s", student_id, exc)
        return None


# ---------------------------------------------------------------------------
# Format curriculum names
# ---------------------------------------------------------------------------

def format_curriculum(text):
    match = re.match(r"^Bachelor of.*?(?:(\()| in )(.*)", text)

    if match:
        was_separated_by_paren = match.group(1)
        cleaned = match.group(2)

        # 1. ONLY remove a trailing ')' if it was separated by a parenthesis
        # AND if there is an extra unmatched closing parenthesis.
        if was_separated_by_paren:
            if cleaned.endswith(")") and cleaned.count(")") > cleaned.count("("):
                cleaned = cleaned.rstrip(")")

        # 2. NEW RULE: Check if it's an Engineering degree but "Engineering" is missing from the cleaned name
        # (We check for 'Efngineering' just to safely catch that typo in your data!)
        if re.search(r"engineering", text, re.IGNORECASE) or "Efngineering" in text:
            if "Engineering" not in cleaned:
                # Smart insert: If there is a trailing parenthesis tag, put "Engineering" BEFORE it.
                # Otherwise, just add it to the end.
                paren_match = re.search(r"(\s*\(.*\))$", cleaned)
                if paren_match:
                    cleaned = cleaned[:paren_match.start()] + " Engineering" + paren_match.group(1)
                else:
                    cleaned += " Engineering"

        return cleaned

    return text


# ---------------------------------------------------------------------------
# Student ID parsing
# ---------------------------------------------------------------------------

def parse_student_id(raw: str):
    """
    Accept '69010001' or '69010001@kmitl.ac.th'.
    Returns the 8-digit string, or raises ValueError.
    """
    raw = raw.strip()

    # Strip @kmitl.ac.th suffix (case-insensitive)
    if "@" in raw:
        local, domain = raw.split("@", 1)
        if domain.lower() != "kmitl.ac.th":
            raise ValueError("Email domain must be @kmitl.ac.th")
        raw = local.strip()

    if not re.fullmatch(r"\d{8}", raw):
        raise ValueError("Student ID must be exactly 8 digits (e.g. 69010001)")

    return raw


def student_id_to_dn(student_id: str):
    """
    Build the LDAP distinguished name for a KMITL student.

    ID format: YY FF XXXX
               └─ YY = admission year
                  └─ FF = faculty code (digits 3-4, 1-indexed)
                          └─ XXXX = sequence
    """
    faculty_code = student_id[2:4]   # digits at position 3–4 (0-indexed: [2:4])
    faculty_ou   = FACULTY_MAP.get(faculty_code)

    if faculty_ou is None:
        raise ValueError(
            f"Unknown faculty code '{faculty_code}'. "
            f"Known codes: {', '.join(sorted(FACULTY_MAP))}"
        )

    dn = (
        f"uid={student_id},"
        f"ou=Student,"
        f"ou={faculty_ou},"
        f"ou=bkk,"
        f"dc=kmitl,dc=ac,dc=th"
    )
    return dn, faculty_code, faculty_ou


# ---------------------------------------------------------------------------
# LDAP helpers
# ---------------------------------------------------------------------------

def _build_server():
    tls = None
    if LDAP_CONFIG["USE_TLS"] or LDAP_CONFIG["USE_SSL"]:
        import ssl
        tls = Tls(validate=ssl.CERT_REQUIRED)

    return Server(
        LDAP_CONFIG["SERVER_HOST"],
        port=LDAP_CONFIG["SERVER_PORT"],
        use_ssl=LDAP_CONFIG["USE_SSL"],
        tls=tls,
        get_info=ALL,
        connect_timeout=LDAP_CONFIG["TIMEOUT"],
    )


def kmitl_authenticate(raw_input: str, password: str):
    """
    Authenticate a KMITL student against the university LDAP.

    Returns:
        (True,  info_dict)        on success
        (False, error_str)        on failure

    info_dict keys: student_id, faculty_code, faculty_ou, faculty_name, dn
    """
    if not raw_input or not password:
        return False, "Student ID and password are required."

    # --- Parse student ID ---
    try:
        student_id = parse_student_id(raw_input)
    except ValueError as exc:
        return False, str(exc)

    # --- Resolve faculty ---
    try:
        dn, faculty_code, faculty_ou = student_id_to_dn(student_id)
    except ValueError as exc:
        return False, str(exc)

    logger.debug("KMITL LDAP: attempting bind as %s", dn)

    # --- Bind as the student ---
    try:
        server = _build_server()
        conn = Connection(
            server,
            user=dn,
            password=password,
            authentication=SIMPLE,
            auto_bind=AUTO_BIND_NO_TLS,
            raise_exceptions=True,
        )
        if LDAP_CONFIG["USE_TLS"]:
            conn.start_tls()

        # Optionally fetch additional attributes while we have an open connection
        conn.search(
            search_base=dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["cn", "mail", "uid"],
        )
        extra = {}
        if conn.entries:
            entry = conn.entries[0]
            for attr in ("cn", "mail", "uid"):
                try:
                    val = entry[attr].value
                    extra[attr] = val if isinstance(val, str) else (val[0] if val else "")
                except Exception:
                    extra[attr] = ""

        conn.unbind()

        info = {
            "student_id":   student_id,
            "faculty_code": faculty_code,
            "faculty_ou":   faculty_ou,
            "dn":           dn,
            "cn":           extra.get("cn", ""),
            "mail":         extra.get("mail", f"{student_id}@kmitl.ac.th"),
        }
        return True, info

    except LDAPBindError:
        return False, "Invalid credentials. Check your student ID and password."
    except LDAPSocketOpenError:
        logger.error(
            "KMITL LDAP: could not connect to %s:%s",
            LDAP_CONFIG["SERVER_HOST"], LDAP_CONFIG["SERVER_PORT"]
        )
        return False, "Cannot reach the KMITL authentication server. Try again later."
    except LDAPException as exc:
        logger.exception("KMITL LDAP error")
        return False, f"Authentication error: {exc}"


# ---------------------------------------------------------------------------
# CTFd user provisioning
# ---------------------------------------------------------------------------

def _get_or_create_ctfd_user(info: dict):
    """Find or auto-create a CTFd user from LDAP info."""
    student_id = info["student_id"]
    email      = info["mail"] or f"{student_id}@kmitl.ac.th"
    # Display name: prefer the LDAP 'cn'; fall back to student ID
    display_name = info.get("cn") or student_id

    user = Users.query.filter(
        (Users.name == student_id) | (Users.email == email)
    ).first()

    if user:
        return user

    if not LDAP_CONFIG["AUTO_PROVISION"]:
        return None

    student_id = info["student_id"]
    curriculum = get_student_curriculum(student_id)
    formatted_curriculum = None

    if curriculum:
        curriculum = format_curriculum(curriculum)
        formatted_curriculum = curriculum

    user = Users(
        name=display_name,
        email=email,
        password="__ldap__",   # sentinel — never matches bcrypt
        type="user",
        verified=True,
        hidden=False,
        affiliation=formatted_curriculum
    )
    db.session.add(user)
    db.session.commit()
    logger.info(
        "KMITL LDAP: auto-provisioned CTFd user '%s' (%s / %s)",
        student_id, info["faculty_name"], email
    )
    return user


# ---------------------------------------------------------------------------
# Login page template
# ---------------------------------------------------------------------------

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login — {{ ctf_name }}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh; display: flex; align-items: center; justify-content: center;
      background: linear-gradient(135deg, #0d1b2a 0%, #1b2838 60%, #0d2137 100%);
      font-family: 'Segoe UI', system-ui, sans-serif; color: #e0e6f0;
    }
    .card {
      width: 100%; max-width: 400px; padding: 2.5rem 2rem;
      background: rgba(255,255,255,.05); border: 1px solid rgba(255,255,255,.1);
      border-radius: 16px; backdrop-filter: blur(12px);
      box-shadow: 0 8px 40px rgba(0,0,0,.5);
    }
    .logo { text-align: center; margin-bottom: 1.5rem; }
    .logo h1 { font-size: 1.6rem; font-weight: 700; color: #fff; }
    .logo p  { font-size: .8rem; color: #7fa8cc; margin-top: .25rem; letter-spacing: .05em; }
    .alert {
      padding: .65rem 1rem; border-radius: 8px; margin-bottom: 1rem;
      font-size: .875rem; background: rgba(220,60,60,.25);
      border: 1px solid rgba(220,60,60,.4); color: #ffaaaa;
    }
    label { display: block; font-size: .8rem; color: #8aaec8; margin-bottom: .35rem; font-weight: 600; letter-spacing: .04em; }
    input[type=text], input[type=password] {
      width: 100%; padding: .65rem .9rem; margin-bottom: 1.2rem;
      background: rgba(255,255,255,.07); border: 1px solid rgba(255,255,255,.15);
      border-radius: 8px; color: #e0e6f0; font-size: 1rem;
      transition: border-color .2s;
    }
    input:focus { outline: none; border-color: #4a9eda; background: rgba(74,158,218,.08); }
    input::placeholder { color: #456; }
    .btn {
      width: 100%; padding: .75rem; border: none; border-radius: 8px; cursor: pointer;
      font-size: 1rem; font-weight: 600; letter-spacing: .04em;
      background: linear-gradient(90deg, #1a6fa8, #2e90d0);
      color: #fff; transition: opacity .2s;
    }
    .btn:hover { opacity: .88; }
    .hint {
      margin-top: 1.2rem; padding: .75rem 1rem;
      background: rgba(255,255,255,.04); border-radius: 8px;
      font-size: .78rem; color: #6a8faa; line-height: 1.6;
    }
    .hint code { background: rgba(255,255,255,.1); padding: .1rem .4rem; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>🏁 {{ ctf_name }}</h1>
      <p>KMITL Student Portal</p>
    </div>

    {% for msg in messages %}
    <div class="alert">{{ msg }}</div>
    {% endfor %}

    <form method="POST" action="/login">
      <input type="hidden" name="nonce" value="{{ nonce }}">

      <label for="name">Student ID</label>
      <input
        id="name" type="text" name="name"
        placeholder="69010001  or  69010001@kmitl.ac.th"
        autocomplete="username" autofocus required
      >

      <label for="password">Password</label>
      <input
        id="password" type="password" name="password"
        placeholder="Your KMITL account password"
        autocomplete="current-password" required
      >

      <button class="btn" type="submit">Sign in with KMITL Account</button>
    </form>

    <div class="hint">
      Use your <strong>KMITL student ID</strong> and password.<br>
      Accepted formats: <code>69010001</code> or <code>69010001@kmitl.ac.th</code>
    </div>
  </div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Admin test panel template
# ---------------------------------------------------------------------------

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>KMITL LDAP — Admin</title>
  <style>
    body { background: #0d1b2a; color: #d0dde8; font-family: monospace; padding: 2rem; }
    h2  { color: #4a9eda; margin-bottom: 1rem; }
    h3  { color: #7fbde0; margin: 1.5rem 0 .5rem; }
    a   { color: #4a9eda; }
    pre {
      background: #0a1520; border: 1px solid #1e3a52; border-radius: 8px;
      padding: 1rem; white-space: pre-wrap; font-size: .85rem;
    }
    table { border-collapse: collapse; width: 100%; max-width: 700px; }
    th, td { padding: .4rem .8rem; border: 1px solid #1e3a52; text-align: left; }
    th { background: #0a1520; color: #4a9eda; }
    input[type=text], input[type=password] {
      padding: .45rem .7rem; background: #0a1520; border: 1px solid #1e3a52;
      border-radius: 6px; color: #d0dde8; width: 220px; margin-right: .5rem;
    }
    button {
      padding: .45rem 1rem; background: #1a6fa8; border: none;
      border-radius: 6px; color: #fff; cursor: pointer;
    }
    button:hover { background: #2e90d0; }
    .faculty-grid {
      display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: .4rem; max-width: 700px;
    }
    .faculty-item {
      background: #0a1520; border: 1px solid #1e3a52; border-radius: 6px;
      padding: .4rem .7rem; font-size: .8rem;
    }
    .code { color: #4a9eda; font-weight: bold; }
  </style>
</head>
<body>
  <h2>🔌 KMITL LDAP Plugin — Admin Panel</h2>
  <p><a href="/admin/plugins">← Back to plugins</a></p>

  <h3>Server Configuration</h3>
  <table>
    <tr><th>Setting</th><th>Value</th></tr>
    <tr><td>Server</td><td>{{ config.SERVER_HOST }}:{{ config.SERVER_PORT }}</td></tr>
    <tr><td>SSL</td><td>{{ config.USE_SSL }}</td></tr>
    <tr><td>STARTTLS</td><td>{{ config.USE_TLS }}</td></tr>
    <tr><td>Base DN</td><td>{{ config.BASE_DN }}</td></tr>
    <tr><td>Auto-provision</td><td>{{ config.AUTO_PROVISION }}</td></tr>
    <tr><td>Allow local admin</td><td>{{ config.ALLOW_LOCAL_ADMIN }}</td></tr>
  </table>

  <h3>Faculty Codes</h3>
  <div class="faculty-grid">
    {% for code, name in faculties.items() %}
    <div class="faculty-item"><span class="code">{{ code }}</span> — {{ name }}</div>
    {% endfor %}
  </div>

  <h3>Test Connection</h3>
  <form method="POST">
    <input type="hidden" name="action" value="test_conn">
    <button type="submit">Ping LDAP server</button>
  </form>

  <h3>Test Student Authentication</h3>
  <form method="POST">
    <input type="hidden" name="action" value="test_user">
    <input type="text"     name="test_username" placeholder="69010001 or @kmitl.ac.th">
    <input type="password" name="test_password"  placeholder="password">
    <button type="submit">Test Login</button>
  </form>

  {% if result %}
  <h3>Result</h3>
  <pre>{{ result }}</pre>
  {% endif %}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------

def load(app):
    ldap_bp = Blueprint("kmitl_ldap", __name__)

    # ------------------------------------------------------------------ #
    # /login override                                                       #
    # ------------------------------------------------------------------ #
    @app.route("/login", methods=["GET", "POST"], endpoint="auth.login_override")
    def login_override():
        from CTFd.utils.security.csrf import generate_nonce

        if not get_config("setup"):
            return redirect(url_for("views.setup"))

        ctf_name = get_config("ctf_name") or "CTF"

        if request.method == "GET":
            nonce = generate_nonce()
            session["nonce"] = nonce
            return render_template_string(
                LOGIN_TEMPLATE, nonce=nonce, ctf_name=ctf_name, messages=[]
            )

        # ---------- POST ----------
        raw_input = request.form.get("name", "").strip()
        password  = request.form.get("password", "")
        messages  = []

        # 1. Local User Fallback
        # Check if the user exists locally and has a valid CTFd password
        local = Users.query.filter_by(name=raw_input).first()
        if local:
            from CTFd.utils.crypto import verify_password
            # LDAP-provisioned users have '__ldap__' as their password hash.
            # verify_password will naturally fail for them, allowing the script to fall through to LDAP.
            if verify_password(password, local.password):
                login_user(local)
                logger.info("KMITL LDAP: user '%s' logged in via local CTFd account", raw_input)
                return redirect(url_for("challenges.listing"))

        # 2. LDAP Authentication (Falls through to here if local auth fails or user doesn't exist)
        success, result = kmitl_authenticate(raw_input, password)

        if not success:
            messages.append(result)
            nonce = generate_nonce()
            session["nonce"] = nonce
            return render_template_string(
                LOGIN_TEMPLATE, nonce=nonce, ctf_name=ctf_name, messages=messages
            ), 401

        # Provision / fetch CTFd user
        ctfd_user = _get_or_create_ctfd_user(result)
        if ctfd_user is None:
            messages.append("No CTFd account found. Contact an administrator.")
            nonce = generate_nonce()
            session["nonce"] = nonce
            return render_template_string(
                LOGIN_TEMPLATE, nonce=nonce, ctf_name=ctf_name, messages=messages
            ), 403

        login_user(ctfd_user)
        log(
            "logins",
            "[{date}] {ip} - {name} ({extra}) logged in via KMITL LDAP\n",
            name=result["student_id"],
            extra=result["faculty_name"],
        )
        return redirect(url_for("challenges.listing"))

    app.view_functions["auth.login"] = login_override

    # ------------------------------------------------------------------ #
    # /register — disabled                                                  #
    # ------------------------------------------------------------------ #
    @app.route("/register", methods=["GET", "POST"], endpoint="auth.register_override")
    def register_override():
        return render_template_string(
            LOGIN_TEMPLATE,
            nonce="",
            ctf_name=get_config("ctf_name") or "CTF",
            messages=["Self-registration is disabled. Use your KMITL account to log in."],
        )

    app.view_functions["auth.register"] = register_override

    # ------------------------------------------------------------------ #
    # Admin panel at /admin/plugins/ldap                                   #
    # ------------------------------------------------------------------ #
    @ldap_bp.route("/admin/plugins/ldap", methods=["GET", "POST"])
    @admins_only
    def ldap_admin():
        result = None

        if request.method == "POST":
            action = request.form.get("action")

            if action == "test_conn":
                try:
                    server = _build_server()
                    conn = Connection(
                        server,
                        auto_bind=AUTO_BIND_NO_TLS,
                        raise_exceptions=True,
                    )
                    result = (
                        f"✅ Connected to {LDAP_CONFIG['SERVER_HOST']}:{LDAP_CONFIG['SERVER_PORT']}\n"
                        f"Server responded. Anonymous bind succeeded.\n"
                        f"(Student authentication uses per-user bind, not anonymous.)"
                    )
                    conn.unbind()
                except LDAPException as exc:
                    result = f"❌ Connection failed:\n{exc}"

            elif action == "test_user":
                test_id = request.form.get("test_username", "").strip()
                test_pw = request.form.get("test_password", "")
                ok, data = kmitl_authenticate(test_id, test_pw)
                if ok:
                    result = (
                        f"✅ Authentication succeeded!\n\n"
                        f"  Student ID   : {data['student_id']}\n"
                        f"  Faculty code : {data['faculty_code']}\n"
                        f"  Faculty OU   : {data['faculty_ou']}\n"
                        f"  Faculty name : {data['faculty_name']}\n"
                        f"  DN           : {data['dn']}\n"
                        f"  CN (name)    : {data['cn']}\n"
                        f"  Email        : {data['mail']}\n"
                    )
                    ctfd_u = Users.query.filter_by(name=data["student_id"]).first()
                    result += f"\n  CTFd account : {'EXISTS (id=' + str(ctfd_u.id) + ')' if ctfd_u else 'not yet created'}"
                else:
                    # Show the DN we would have tried, to help debug config
                    try:
                        sid = parse_student_id(test_id)
                        dn, fc, fo = student_id_to_dn(sid)
                        result = f"❌ Authentication failed:\n  {data}\n\nWould have used DN:\n  {dn}"
                    except ValueError:
                        result = f"❌ {data}"

        return render_template_string(
            ADMIN_TEMPLATE,
            config=LDAP_CONFIG,
            faculties=FACULTY_DISPLAY,
            result=result,
        )

    app.register_blueprint(ldap_bp)

    logger.info(
        "KMITL LDAP plugin loaded — server: %s:%s",
        LDAP_CONFIG["SERVER_HOST"],
        LDAP_CONFIG["SERVER_PORT"],
    )