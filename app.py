from datetime import date
import os
from pathlib import Path
import re
from flask import (
    Flask,
    flash,
    redirect,
    render_template_string,
    request,
    send_from_directory,
    session,
    url_for,
)
import pymysql
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "qshe_super_secret_key_change_in_production"

# ---------- UPLOAD CONFIGURATION ----------
UPLOAD_FOLDER = Path(__file__).with_name("uploads")
UPLOAD_FOLDER.mkdir(exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}


def allowed_file(filename):
  return (
      "." in filename
      and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
  )


# ---------- PASSWORD VALIDATION FUNCTION ----------


def validate_password(password):
  if len(password) < 8:
    return False, "Password must be at least 8 characters long."
  if not re.search(r"[A-Za-z]", password):
    return False, "Password must contain at least one letter."
  if not re.search(r"\d", password):
    return False, "Password must contain at least one number."
  if not re.search(r"[^A-Za-z0-9]", password):
    return (
        False,
        (
            "Password must contain at least one symbol (e.g., !, @, #, $, *, ?"
            " etc.)."
        ),
    )
  return True, "Password is valid."


# ---------- DATABASE CONFIGURATION ----------
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "",  # Default XAMPP MySQL has no password
    "database": "qshet_db",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}


def get_db():
  return pymysql.connect(**DB_CONFIG)


def init_db():
  conn = get_db()
  try:
    with conn.cursor() as cursor:
      # Users table
      cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(100) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(20) NOT NULL
                ) ENGINE=InnoDB;
            """)

      # Safety reports table
      cursor.execute("""
                CREATE TABLE IF NOT EXISTS safety_reports (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(150) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    description TEXT,
                    filename VARCHAR(255),
                    status VARCHAR(20) DEFAULT 'Open',
                    created_at VARCHAR(20) NOT NULL
                ) ENGINE=InnoDB;
            """)

      # Documents table
      cursor.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(150) NOT NULL,
                    doc_type VARCHAR(50) NOT NULL,
                    filename VARCHAR(255),
                    review_date VARCHAR(20)
                ) ENGINE=InnoDB;
            """)

      # Training table
      cursor.execute("""
                CREATE TABLE IF NOT EXISTS training (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    employee VARCHAR(100) NOT NULL,
                    course VARCHAR(150) NOT NULL,
                    filename VARCHAR(255),
                    expiry_date VARCHAR(20)
                ) ENGINE=InnoDB;
            """)

      # CIDB / Protege Document Uploads table
      cursor.execute("""
                CREATE TABLE IF NOT EXISTS cidb_uploads (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    title VARCHAR(150) NOT NULL,
                    filename VARCHAR(255) NOT NULL,
                    uploaded_at VARCHAR(20) NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                ) ENGINE=InnoDB;
            """)

      # Auto-patch existing tables if filename column is missing
      for tbl in ["safety_reports", "documents", "training"]:
        cursor.execute(f"SHOW COLUMNS FROM {tbl} LIKE 'filename'")
        if not cursor.fetchone():
          cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN filename VARCHAR(255)")

      # Seed default admin if no users exist
      cursor.execute("SELECT COUNT(*) AS cnt FROM users")
      if cursor.fetchone()["cnt"] == 0:
        admin_pass = generate_password_hash("Admin@123")
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s,"
            " 'admin')",
            ("admin", admin_pass),
        )

    conn.commit()
  finally:
    conn.close()


# ---------- WEBSITE TEMPLATE ----------

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QSHET Management System</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0; font-family: Arial, sans-serif;
    background: #f3f6f5; color: #24332e;
    display: flex; flex-direction: column; min-height: 100vh;
}
header {
    background: #183b35; color: white;
    padding: 22px 5%;
    display: flex; justify-content: space-between; align-items: center;
}
header h1 { margin: 0 0 6px; font-size: 24px; }
header p { margin: 0; color: #d5e7df; }
.user-info { text-align: right; font-size: 14px; }
.user-info a { color: #ffd166; text-decoration: none; font-weight: bold; }
nav {
    background: white; padding: 14px 5%;
    display: flex; flex-wrap: wrap; gap: 18px;
    border-bottom: 1px solid #ddd;
}
nav a { color: #23594b; text-decoration: none; font-weight: bold; }
main { max-width: 1100px; margin: 28px auto; padding: 0 18px; flex: 1; }
.cards {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px;
}
.card {
    background: white; padding: 20px;
    border-radius: 12px; margin-bottom: 18px;
    box-shadow: 0 2px 8px #0000000a;
    text-decoration: none; color: inherit; display: block;
    transition: transform 0.2s, box-shadow 0.2s;
}
.card:hover {
    transform: translateY(-3px);
    box-shadow: 0 4px 12px #00000015;
}
.panel {
    background: white; padding: 20px;
    border-radius: 12px; margin-bottom: 18px;
    box-shadow: 0 2px 8px #0000000a;
}
.number { font-size: 30px; font-weight: bold; color: #23594b; }
label { display: block; margin-top: 12px; font-weight: bold; }
input, select, textarea {
    width: 100%; padding: 10px; margin-top: 6px;
    border: 1px solid #ccd5d1; border-radius: 6px;
}
button, .btn {
    background: #23594b; color: white; border: 0;
    padding: 11px 18px; margin-top: 14px;
    border-radius: 6px; cursor: pointer; text-decoration: none; display: inline-block;
}
.btn-danger { background: #d90429; }
.btn-sm { padding: 6px 12px; margin-top: 4px; font-size: 12px; }
table { width: 100%; border-collapse: collapse; background: white; }
th, td { padding: 11px; border-bottom: 1px solid #e2e8e5; text-align: left; }
.clickable-row { cursor: pointer; transition: background 0.2s; }
.clickable-row:hover { background: #f0f7f4; }
.table-wrap { overflow-x: auto; }
.badge { background: #e4eee8; padding: 5px 8px; border-radius: 6px; }
.muted { color: #66756e; }
.alert { background: #ffccd5; color: #780016; padding: 10px; border-radius: 6px; margin-bottom: 15px; }

/* Footer Styling */
footer {
    background: #183b35; color: #d5e7df; text-align: center;
    padding: 16px 5%; margin-top: 40px; font-size: 13px;
    border-top: 3px solid #23594b;
}
footer strong { color: #ffd166; }

/* Password Eye Icon Styling */
.password-container {
    position: relative;
    width: 100%;
}
.password-container input {
    width: 100%;
    padding-right: 42px;
}
.toggle-eye-btn {
    position: absolute; right: 10px; top: 53%;
    transform: translateY(-50%); cursor: pointer;
    background: none; border: none; padding: 0; margin: 0;
    display: flex; align-items: center; justify-content: center; color: #333;
}
.toggle-eye-btn svg {
    width: 22px; height: 22px; stroke: currentColor;
    stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round;
}

/* Password Strength Indicator Styles */
.strength-meter { margin-top: 6px; font-size: 13px; font-weight: bold; }
.text-weak { color: #d90429; }
.text-moderate { color: #f77f00; }
.text-strong { color: #2a9d8f; }

/* Modal Styles for Enlarging Data */
.modal-overlay {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center;
    z-index: 1000;
}
.modal-content {
    background: white; padding: 25px; border-radius: 12px; max-width: 500px; width: 90%;
    box-shadow: 0 5px 15px rgba(0,0,0,0.3); position: relative;
}
.modal-close {
    position: absolute; top: 12px; right: 16px; font-size: 22px; cursor: pointer; color: #666;
    font-weight: bold;
}
.modal-field { margin-bottom: 12px; }
.modal-field label { font-weight: bold; color: #183b35; margin-bottom: 2px; }
.modal-field div { background: #f8faf9; padding: 8px 12px; border-radius: 6px; border: 1px solid #e0e8e4; }
</style>
</head>
<body>
<header>
    <div>
        <h1>QSHET Management System</h1>
        <p>Quality · Safety · Health · Environment · Traffic</p>
    </div>
    <div class="user-info">
        {% if session.get('user_id') %}
            Logged in as: <strong>{{ session.get('username') }}</strong> ({{ session.get('role')|capitalize }})<br>
            <a href="/logout">Logout</a>
        {% else %}
            <a href="/login">Login</a> | <a href="/register">Register</a>
        {% endif %}
    </div>
</header>
<nav>
    <a href="/">Dashboard</a>
    {% if session.get('role') == 'admin' %}
        <a href="/safety">Safety Reports</a>
        <a href="/documents">Document Records</a>
        <a href="/training">Training & Compliance</a>
        <a href="/manage-cidb">All Protege CIDB Records</a>
        <a href="/manage-users">Manage Users & Passwords</a>
    {% elif session.get('role') == 'protege' %}
        <a href="/my-cidb">My CIDB Documents</a>
    {% endif %}
</nav>
<main>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        {% for message in messages %}
          <div class="alert">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {{ content | safe }}
</main>

<footer>
    <p style="margin: 0;">&copy; 2026 QSHET Management System. Designed & Developed by <strong>Nur Amira Najwa Binti Zulkhibree</strong> — <strong>PROTÉGÉ Trainee</strong> at Maltimur Aktif Unggul JV Sdn Bhd (Sarawak-Sabah Link Road Project 2).</p>
</footer>

<!-- Popup Detail Modal -->
<div id="detailModal" class="modal-overlay" onclick="closeModal(event)">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect()">&times;</span>
        <h3 style="margin-top:0; color:#183b35;" id="modalTitle">Report Details</h3>
        <div id="modalBody"></div>
    </div>
</div>

<!-- SVG Eye Definitions -->
<svg style="display:none;">
  <g id="icon-eye-open">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
    <circle cx="12" cy="12" r="3"></circle>
  </g>
  <g id="icon-eye-off">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
    <line x1="1" y1="1" x2="23" y2="23"></line>
  </g>
</svg>

<script>
function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const svg = btn.querySelector('svg');
    if (input.type === "password") {
        input.type = "text";
        svg.innerHTML = '<use href="#icon-eye-off"></use>';
    } else {
        input.type = "password";
        svg.innerHTML = '<use href="#icon-eye-open"></use>';
    }
}

function checkPasswordStrength(password) {
    const indicator = document.getElementById("strength-indicator");
    if (!indicator) return;

    if (password.length === 0) {
        indicator.textContent = "";
        return;
    }

    let score = 0;
    if (password.length >= 8) score++;
    if (/[A-Za-z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 2) {
        indicator.textContent = "Strength: Weak ❌ (Needs letters, numbers & symbols)";
        indicator.className = "strength-meter text-weak";
    } else if (score === 3) {
        indicator.textContent = "Strength: Moderate ⚠️ (Add a mix of symbols or length)";
        indicator.className = "strength-meter text-moderate";
    } else {
        indicator.textContent = "Strength: Strong ✅";
        indicator.className = "strength-meter text-strong";
    }
}

function showReportDetails(id, title, category, description, filename, status, created_at) {
    const modalBody = document.getElementById('modalBody');
    let fileHtml = filename ? `<a href="/uploads/${filename}" target="_blank">View Attached File (${filename})</a>` : 'None';
    
    modalBody.innerHTML = `
        <div class="modal-field"><label>Report ID</label><div>#${id}</div></div>
        <div class="modal-field"><label>Title</label><div>${title}</div></div>
        <div class="modal-field"><label>Category</label><div>${category}</div></div>
        <div class="modal-field"><label>Description</label><div>${description || 'No description provided'}</div></div>
        <div class="modal-field"><label>Attached File</label><div>${fileHtml}</div></div>
        <div class="modal-field"><label>Status</label><div><strong>${status}</strong></div></div>
        <div class="modal-field"><label>Created Date</label><div>${created_at}</div></div>
    `;
    document.getElementById('detailModal').style.display = 'flex';
}

function closeModal(event) {
    if (event.target.id === 'detailModal') {
        document.getElementById('detailModal').style.display = 'none';
    }
}

function closeModalDirect() {
    document.getElementById('detailModal').style.display = 'none';
}
</script>
</body>
</html>
"""


def page(content, **data):
  return render_template_string(PAGE, content=content, **data)


def table(headers, rows):
  html = "<div class='table-wrap'><table><thead><tr>"
  for header in headers:
    html += f"<th>{header}</th>"
  html += "</tr></thead><tbody>"

  for row in rows:
    html += "<tr>"
    if isinstance(row, dict):
      values = list(row.values())
    else:
      values = row

    for value in values:
      html += f"<td>{value if value is not None else '-'}</td>"
    html += "</tr>"

  return html + "</tbody></table></div>"


# ---------- AUTHENTICATION & REGISTRATION ROUTES ----------


@app.route("/login", methods=["GET", "POST"])
def login():
  if request.method == "POST":
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db()
    try:
      with conn.cursor() as db:
        db.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = db.fetchone()
    finally:
      conn.close()

    if user and check_password_hash(user["password"], password):
      session["user_id"] = user["id"]
      session["username"] = user["username"]
      session["role"] = user["role"]
      return redirect(url_for("dashboard"))
    else:
      flash("Invalid username or password")

  content = """
    <h2>Login</h2>
    <section class="panel" style="max-width: 400px; margin: auto;">
    <form method="post">
        <label>Username</label>
        <input name="username" required>
        
        <label>Password</label>
        <div class="password-container">
            <input type="password" id="login_pass" name="password" required>
            <button type="button" class="toggle-eye-btn" onclick="togglePasswordVisibility('login_pass', this)">
                <svg viewBox="0 0 24 24"><use href="#icon-eye-open"></use></svg>
            </button>
        </div>

        <button type="submit">Login</button>
    </form>
    <p class="muted" style="margin-top: 15px; font-size: 13px;">
        Don't have an account? <a href="/register">Register here</a>
    </p>
    </section>
    """
  return page(content)


@app.route("/register", methods=["GET", "POST"])
def register():
  if request.method == "POST":
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "protege")

    if not username or not password:
      flash("Username and password are required.")
      return redirect(url_for("register"))

    is_valid, message = validate_password(password)
    if not is_valid:
      flash(message)
      return redirect(url_for("register"))

    hashed_password = generate_password_hash(password)

    conn = get_db()
    try:
      with conn.cursor() as db:
        db.execute("SELECT id FROM users WHERE username = %s", (username,))
        if db.fetchone():
          flash("Username already taken. Please choose another username.")
          return redirect(url_for("register"))

        db.execute(
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
            (username, hashed_password, role),
        )
      conn.commit()
      flash("Registration successful! You can now log in with your credentials.")
      return redirect(url_for("login"))
    except Exception as e:
      flash(f"Error during registration: {e}")
    finally:
      conn.close()

  content = """
    <h2>Register New Account</h2>
    <section class="panel" style="max-width: 400px; margin: auto;">
    <form method="post">
        <label>Username</label>
        <input name="username" required maxlength="100">
        
        <label>Password</label>
        <div class="password-container">
            <input type="password" id="reg_pass" name="password" required oninput="checkPasswordStrength(this.value)">
            <button type="button" class="toggle-eye-btn" onclick="togglePasswordVisibility('reg_pass', this)">
                <svg viewBox="0 0 24 24"><use href="#icon-eye-open"></use></svg>
            </button>
        </div>
        <div id="strength-indicator" class="strength-meter"></div>
        <p class="muted" style="font-size: 12px; margin-top: 4px;">
            Must be at least 8 characters long and include letters, numbers, and a symbol (e.g., !, @, #, *, ?).
        </p>

        <label>Role</label>
        <select name="role" required>
            <option value="protege">Protege</option>
            <option value="admin">Admin</option>
        </select>

        <button type="submit">Register</button>
    </form>
    <p class="muted" style="margin-top: 15px; font-size: 13px;">
        Already have an account? <a href="/login">Login here</a>
    </p>
    </section>
    """
  return page(content)


@app.route("/logout")
def logout():
  session.clear()
  return redirect(url_for("login"))


# ---------- 1. DASHBOARD ----------


@app.route("/")
def dashboard():
  if "user_id" not in session:
    return redirect(url_for("login"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT COUNT(*) AS cnt FROM safety_reports")
      reports = db.fetchone()["cnt"]

      db.execute(
          "SELECT COUNT(*) AS cnt FROM safety_reports WHERE status='Open'"
      )
      open_reports = db.fetchone()["cnt"]

      db.execute("SELECT COUNT(*) AS cnt FROM documents")
      documents = db.fetchone()["cnt"]

      db.execute("SELECT COUNT(*) AS cnt FROM training")
      courses = db.fetchone()["cnt"]

      db.execute("""
                SELECT id, title, category, description, filename, status, created_at
                FROM safety_reports ORDER BY id DESC LIMIT 5
            """)
      recent = db.fetchall()
  finally:
    conn.close()

  is_admin = session.get("role") == "admin"
  safety_url = "/safety" if is_admin else "#"
  docs_url = "/documents" if is_admin else "#"
  training_url = "/training" if is_admin else "#"

  recent_table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Status</th><th>Date</th></tr></thead><tbody>"
  )
  if recent:
    for r in recent:
      escaped_title = r["title"].replace("'", "\\'")
      escaped_category = r["category"].replace("'", "\\'")
      escaped_desc = (r["description"] or "").replace("'", "\\'").replace("\n", " ")
      escaped_fn = (r["filename"] or "").replace("'", "\\'")

      recent_table_html += f"""
            <tr class="clickable-row" onclick="showReportDetails('{r['id']}', '{escaped_title}', '{escaped_category}', '{escaped_desc}', '{escaped_fn}', '{r['status']}', '{r['created_at']}')">
                <td>{r['id']}</td>
                <td><strong>{r['title']}</strong></td>
                <td>{r['category']}</td>
                <td><span class="badge">{r['status']}</span></td>
                <td>{r['created_at']}</td>
            </tr>
            """
  else:
    recent_table_html += "<tr><td colspan='5' class='muted' style='text-align:center;'>No recent safety reports found.</td></tr>"
  recent_table_html += "</tbody></table></div>"

  content = f"""
    <h2>Dashboard</h2>
    <p class="muted">Welcome back, {session.get('username')}! Overview of QSHET records (Click cards or table rows to view/enlarge details)</p>
    <div class="cards">
        <a href="{safety_url}" class="card">Total Safety Reports
            <div class="number">{reports}</div></a>
        <a href="{safety_url}" class="card">Open Reports
            <div class="number">{open_reports}</div></a>
        <a href="{docs_url}" class="card">Documents
            <div class="number">{documents}</div></a>
        <a href="{training_url}" class="card">Training Records
            <div class="number">{courses}</div></a>
    </div>
    <section class="panel">
        <h3>Recent Safety Reports</h3>
        <p class="muted" style="font-size: 13px; margin-top:-5px; margin-bottom:12px;">Click any row to open and enlarge detailed information.</p>
        {recent_table_html}
    </section>
    """
  return page(content)


# ---------- 2. SAFETY REPORTS (Admin Only) ----------


@app.route("/safety", methods=["GET", "POST"])
def safety():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "")
    description = request.form.get("description", "").strip()
    action = request.form.get("action")
    report_id = request.form.get("report_id")
    file = request.files.get("file")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "delete" and report_id:
          db.execute(
              "SELECT filename FROM safety_reports WHERE id = %s", (report_id,)
          )
          row = db.fetchone()
          if row and row["filename"]:
            f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if f_path.exists():
              os.remove(f_path)
          db.execute("DELETE FROM safety_reports WHERE id = %s", (report_id,))
        elif action == "update" and report_id:
          status = request.form.get("status")
          db.execute(
              "UPDATE safety_reports SET status = %s WHERE id = %s",
              (status, report_id),
          )
        elif title and category in ["Incident", "Inspection", "Hazard"]:
          filename = None
          if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(
                f"safety_{date.today().isoformat()}_{file.filename}"
            )
            file.save(app.config["UPLOAD_FOLDER"] / filename)

          db.execute(
              """
                        INSERT INTO safety_reports
                        (title, category, description, filename, status, created_at)
                        VALUES (%s, %s, %s, %s, 'Open', %s)
                    """,
              (
                  title,
                  category,
                  description,
                  filename,
                  date.today().isoformat(),
              ),
          )
      conn.commit()
    finally:
      conn.close()

    return redirect(url_for("safety"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("""
                SELECT id, title, category, description, filename, status, created_at
                FROM safety_reports ORDER BY id DESC
            """)
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Description</th><th>File</th><th>Status</th><th>Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = (
        f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
        if r["filename"]
        else "-"
    )
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td>{r['category']}</td>
            <td>{r['description'] or '-'}</td>
            <td>{file_link}</td>
            <td>
                <form method="post" style="display:inline;">
                    <input type="hidden" name="action" value="update">
                    <input type="hidden" name="report_id" value="{r['id']}">
                    <select name="status" onchange="this.form.submit()" style="padding:4px; width:auto;">
                        <option value="Open" {'SELECTED' if r['status']=='Open' else ''}>Open</option>
                        <option value="Resolved" {'SELECTED' if r['status']=='Resolved' else ''}>Resolved</option>
                        <option value="Closed" {'SELECTED' if r['status']=='Closed' else ''}>Closed</option>
                    </select>
                </form>
            </td>
            <td>{r['created_at']}</td>
            <td>
                <form method="post" onsubmit="return confirm('Delete this report?');" style="display:inline;">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="report_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>Safety Reports</h2>
    <section class="panel">
    <h3>Submit a Report</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Report Title</label>
        <input name="title" required maxlength="150">
        <label>Category</label>
        <select name="category" required>
            <option value="Incident">Incident</option>
            <option value="Inspection">Safety Inspection</option>
            <option value="Hazard">Hazard</option>
        </select>
        <label>Description</label>
        <textarea name="description" rows="3" maxlength="3000"></textarea>
        <label>Attach Document or Picture (Optional)</label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
        <button type="submit">Save Report</button>
    </form>
    </section>
    <section class="panel"><h3>Report Records</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- 3. DOCUMENT RECORDS (Admin Only) ----------


@app.route("/documents", methods=["GET", "POST"])
def documents():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    action = request.form.get("action")
    doc_id = request.form.get("doc_id")
    file = request.files.get("file")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "delete" and doc_id:
          db.execute("SELECT filename FROM documents WHERE id = %s", (doc_id,))
          row = db.fetchone()
          if row and row["filename"]:
            f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if f_path.exists():
              os.remove(f_path)
          db.execute("DELETE FROM documents WHERE id = %s", (doc_id,))
        else:
          title = request.form.get("title", "").strip()
          doc_type = request.form.get("doc_type", "").strip()
          review_date = request.form.get("review_date", "")
          if title and doc_type:
            filename = None
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"doc_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)

            db.execute(
                """
                            INSERT INTO documents (title, doc_type, filename, review_date)
                            VALUES (%s, %s, %s, %s)
                        """,
                (title, doc_type, filename, review_date or None),
            )
      conn.commit()
    finally:
      conn.close()

    return redirect(url_for("documents"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute(
          "SELECT id, title, doc_type, filename, review_date FROM documents"
          " ORDER BY id DESC"
      )
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Type</th><th>File</th><th>Review"
      " Date</th><th>Action</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = (
        f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
        if r["filename"]
        else "-"
    )
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td>{r['doc_type']}</td>
            <td>{file_link}</td>
            <td>{r['review_date'] or '-'}</td>
            <td>
                <form method="post" onsubmit="return confirm('Delete this document?');">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="doc_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>Document Records</h2>
    <section class="panel">
    <h3>Add Document Record</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Document Title</label>
        <input name="title" required maxlength="150">
        <label>Document Type</label>
        <select name="doc_type" required>
            <option value="Policy">Policy</option>
            <option value="Safety Checklist">Safety Checklist</option>
            <option value="Audit Report">Audit Report</option>
            <option value="Certificate">Certificate</option>
            <option value="Other">Other</option>
        </select>
        <label>Next Review Date</label>
        <input type="date" name="review_date">
        <label>Attach Document or Picture (Optional)</label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
        <button type="submit">Save Document Record</button>
    </form>
    </section>
    <section class="panel"><h3>Document List</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- 4. TRAINING & COMPLIANCE (Admin Only) ----------


@app.route("/training", methods=["GET", "POST"])
def training():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    action = request.form.get("action")
    train_id = request.form.get("train_id")
    file = request.files.get("file")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "delete" and train_id:
          db.execute("SELECT filename FROM training WHERE id = %s", (train_id,))
          row = db.fetchone()
          if row and row["filename"]:
            f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if f_path.exists():
              os.remove(f_path)
          db.execute("DELETE FROM training WHERE id = %s", (train_id,))
        else:
          employee = request.form.get("employee", "").strip()
          course = request.form.get("course", "").strip()
          expiry = request.form.get("expiry_date", "")
          if employee and course:
            filename = None
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"training_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)

            db.execute(
                """
                            INSERT INTO training (employee, course, filename, expiry_date)
                            VALUES (%s, %s, %s, %s)
                        """,
                (employee, course, filename, expiry or None),
            )
      conn.commit()
    finally:
      conn.close()

    return redirect(url_for("training"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute(
          "SELECT id, employee, course, filename, expiry_date FROM training"
          " ORDER BY id DESC"
      )
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Employee</th><th>Course</th><th>File</th><th>Expiry"
      " Date</th><th>Action</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = (
        f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
        if r["filename"]
        else "-"
    )
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['employee']}</td>
            <td>{r['course']}</td>
            <td>{file_link}</td>
            <td>{r['expiry_date'] or '-'}</td>
            <td>
                <form method="post" onsubmit="return confirm('Delete this record?');">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="train_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>Training & Compliance</h2>
    <section class="panel">
    <h3>Add Training Record</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Employee Name or Staff ID</label>
        <input name="employee" required maxlength="100">
        <label>Training Course</label>
        <input name="course" required maxlength="150">
        <label>Certificate Expiry Date</label>
        <input type="date" name="expiry_date">
        <label>Attach Certificate / File (Optional)</label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
        <button type="submit">Save Training Record</button>
    </form>
    </section>
    <section class="panel"><h3>Training Records</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- 5. PROTEGE: UPLOAD / REUPLOAD CIDB DOCUMENTS ----------


@app.route("/my-cidb", methods=["GET", "POST"])
def my_cidb():
  if session.get("role") != "protege":
    flash("Access denied. Protege only.")
    return redirect(url_for("dashboard"))

  user_id = session.get("user_id")

  if request.method == "POST":
    action = request.form.get("action")

    if action == "delete":
      doc_id = request.form.get("doc_id")
      conn = get_db()
      try:
        with conn.cursor() as db:
          db.execute(
              "SELECT filename FROM cidb_uploads WHERE id = %s AND user_id = %s",
              (doc_id, user_id),
          )
          row = db.fetchone()
          if row:
            file_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if file_path.exists():
              os.remove(file_path)
            db.execute("DELETE FROM cidb_uploads WHERE id = %s", (doc_id,))
        conn.commit()
      finally:
        conn.close()
      flash("Document deleted successfully.")

    else:
      title = request.form.get("title", "").strip()
      file = request.files.get("file")

      if title and file and allowed_file(file.filename):
        filename = secure_filename(
            f"user_{user_id}_{date.today().isoformat()}_{file.filename}"
        )
        file.save(app.config["UPLOAD_FOLDER"] / filename)

        conn = get_db()
        try:
          with conn.cursor() as db:
            db.execute(
                """
                            INSERT INTO cidb_uploads (user_id, title, filename, uploaded_at)
                            VALUES (%s, %s, %s, %s)
                        """,
                (user_id, title, filename, date.today().isoformat()),
            )
          conn.commit()
        finally:
          conn.close()
        flash("Document uploaded successfully!")
      else:
        flash(
            "Invalid file or missing title. Allowed formats: PNG, JPG, JPEG, PDF."
        )

    return redirect(url_for("my_cidb"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute(
          "SELECT id, title, filename, uploaded_at FROM cidb_uploads WHERE user_id = %s ORDER BY id DESC",
          (user_id,),
      )
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>File</th><th>Uploaded Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td><a href="/uploads/{r['filename']}" target="_blank">View File</a></td>
            <td>{r['uploaded_at']}</td>
            <td>
                <a href="/reupload-cidb/{r['id']}" class="btn btn-sm" style="background:#23594b; text-decoration:none; display:inline-block; margin-top:0;">Re-upload</a>
                <form method="post" onsubmit="return confirm('Delete this document?');" style="display:inline; margin-left:6px;">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="doc_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>My CIDB Card & Document Records</h2>
    <section class="panel">
    <h3>Upload / Re-upload Document (Picture or PDF)</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Document Title (e.g., CIDB Card 2026)</label>
        <input name="title" required maxlength="150">
        <label>Select File (Image or PDF)</label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf" required>
        <button type="submit">Upload Document</button>
    </form>
    <p class="muted" style="margin-top: 10px; font-size: 13px;">If you uploaded a wrong document, click the "Re-upload" button in the table below to replace it.</p>
    </section>
    <section class="panel"><h3>My Uploaded Files</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- 5b. PROTEGE: RE-UPLOAD SPECIFIC CIDB DOCUMENT ----------


@app.route("/reupload-cidb/<int:doc_id>", methods=["GET", "POST"])
def reupload_cidb(doc_id):
  if session.get("role") != "protege":
    flash("Access denied. Protege only.")
    return redirect(url_for("dashboard"))

  user_id = session.get("user_id")

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute(
          "SELECT id, title, filename FROM cidb_uploads WHERE id = %s AND user_id = %s",
          (doc_id, user_id),
      )
      doc = db.fetchone()
  finally:
    conn.close()

  if not doc:
    flash("Document record not found.")
    return redirect(url_for("my_cidb"))

  if request.method == "POST":
    title = request.form.get("title", "").strip()
    file = request.files.get("file")

    if not title:
      flash("Document title is required.")
    else:
      conn = get_db()
      try:
        with conn.cursor() as db:
          if file and file.filename and allowed_file(file.filename):
            old_file_path = app.config["UPLOAD_FOLDER"] / doc["filename"]
            if old_file_path.exists():
              os.remove(old_file_path)

            new_filename = secure_filename(
                f"user_{user_id}_{date.today().isoformat()}_{file.filename}"
            )
            file.save(app.config["UPLOAD_FOLDER"] / new_filename)

            db.execute(
                "UPDATE cidb_uploads SET title = %s, filename = %s, uploaded_at = %s WHERE id = %s",
                (title, new_filename, date.today().isoformat(), doc_id),
            )
          else:
            db.execute(
                "UPDATE cidb_uploads SET title = %s WHERE id = %s",
                (title, doc_id),
            )

          conn.commit()
          flash("Document re-uploaded / updated successfully!")
          return redirect(url_for("my_cidb"))
      finally:
        conn.close()

  content = f"""
    <h2>Re-upload Document</h2>
    <section class="panel" style="max-width: 500px; margin: auto;">
    <form method="post" enctype="multipart/form-data">
        <label>Document Title</label>
        <input name="title" value="{doc['title']}" required maxlength="150">

        <label>Current File</label>
        <p style="margin-top: 4px;"><a href="/uploads/{doc['filename']}" target="_blank">View Current File ({doc['filename']})</a></p>

        <label>Select New File (Optional - Leave blank to keep current file)</label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">

        <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="submit" class="btn" style="margin:0;">Update / Re-upload</button>
            <a href="/my-cidb" class="btn" style="background: #66756e; text-decoration: none; text-align: center; line-height: normal; padding: 11px 18px; margin:0;">Cancel</a>
        </div>
    </form>
    </section>
  """
  return page(content)


# ---------- 6. ADMIN: MONITOR & DELETE ALL PROTEGE UPLOADS ----------


@app.route("/manage-cidb", methods=["GET", "POST"])
def manage_cidb():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    action = request.form.get("action")
    doc_id = request.form.get("doc_id")

    if action == "delete" and doc_id:
      conn = get_db()
      try:
        with conn.cursor() as db:
          db.execute("SELECT filename FROM cidb_uploads WHERE id = %s", (doc_id,))
          row = db.fetchone()
          if row:
            file_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if file_path.exists():
              os.remove(file_path)
            db.execute("DELETE FROM cidb_uploads WHERE id = %s", (doc_id,))
            conn.commit()
            flash("Protege document deleted successfully.")
      finally:
        conn.close()

    return redirect(url_for("manage_cidb"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("""
                SELECT c.id, u.username, c.title, c.filename, c.uploaded_at
                FROM cidb_uploads c
                JOIN users u ON c.user_id = u.id
                ORDER BY c.id DESC
            """)
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Protege Username</th><th>Title</th><th>File</th><th>Uploaded Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td><strong>{r['username']}</strong></td>
            <td>{r['title']}</td>
            <td><a href="/uploads/{r['filename']}" target="_blank">View File</a></td>
            <td>{r['uploaded_at']}</td>
            <td>
                <form method="post" onsubmit="return confirm('Delete this protege document?');" style="display:inline;">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="doc_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>Protege CIDB Card & Document Monitor</h2>
    <section class="panel"><h3>All Protege Uploads</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- 7. ADMIN: MANAGE USERS (LIST, ADD, DELETE) ----------


@app.route("/manage-users", methods=["GET", "POST"])
def manage_users():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    action = request.form.get("action")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "add":
          new_username = request.form.get("new_username", "").strip()
          new_password = request.form.get("new_password", "")
          new_role = request.form.get("new_role", "protege")

          if not new_username or not new_password:
            flash("Username and password are required.")
          else:
            is_valid, message = validate_password(new_password)
            if not is_valid:
              flash(f"Add user failed: {message}")
            else:
              db.execute("SELECT id FROM users WHERE username = %s", (new_username,))
              if db.fetchone():
                flash("Username already taken. Choose another.")
              else:
                hashed_pw = generate_password_hash(new_password)
                db.execute(
                    "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)",
                    (new_username, hashed_pw, new_role),
                )
                conn.commit()
                flash("New user added successfully!")

        elif action == "delete":
          user_id = request.form.get("user_id")
          if user_id:
            if int(user_id) == session.get("user_id"):
              flash("You cannot delete your own active admin account.")
            else:
              db.execute("DELETE FROM users WHERE id = %s", (user_id,))
              conn.commit()
              flash("User account deleted successfully.")
    finally:
      conn.close()

    return redirect(url_for("manage_users"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT id, username, role FROM users ORDER BY id ASC")
      users = db.fetchall()
  finally:
    conn.close()

  table_rows_html = ""
  for u in users:
    is_current = (u['id'] == session.get('user_id'))
    table_rows_html += f"""
        <tr>
            <td>{u['id']}</td>
            <td><strong>{u['username']}</strong></td>
            <td><span class="badge">{u['role'].capitalize()}</span></td>
            <td>
                <a href="/edit-user/{u['id']}" class="btn btn-sm" style="background:#23594b; text-decoration:none; display:inline-block; margin-top:0;">Update</a>
                {'<form method="post" style="display:inline; margin-left:6px;"><input type="hidden" name="action" value="delete"><input type="hidden" name="user_id" value="' + str(u['id']) + '"><button type="submit" class="btn btn-danger btn-sm" onclick="return confirm(\'Delete this user and their records?\');">Delete</button></form>' if not is_current else '<span class="muted" style="margin-left:8px; font-size:12px;">Active</span>'}
            </td>
        </tr>
    """

  add_row_html = f"""
        <tr style="background: #f8faf9;">
            <form method="post">
                <input type="hidden" name="action" value="add">
                <td>#</td>
                <td><input type="text" name="new_username" placeholder="New Username" required style="padding:8px; margin:0; width:100%;"></td>
                <td>
                    <select name="new_role" required style="padding:8px; margin:0; width:100%;">
                        <option value="protege">Protege</option>
                        <option value="admin">Admin</option>
                    </select>
                </td>
                <td>
                    <div style="display:flex; gap:8px;">
                        <input type="password" name="new_password" placeholder="Password (Min 8, #, @)" required style="padding:8px; margin:0; flex:1;">
                        <button type="submit" class="btn btn-sm" style="margin:0; background:#23594b; white-space:nowrap;">Save / Add</button>
                    </div>
                </td>
            </form>
        </tr>
  """

  user_table_html = f"""
    <div class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Role</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {add_row_html}
                {table_rows_html}
            </tbody>
        </table>
    </div>
  """

  content = f"""
    <h2>User Accounts & Password Management</h2>
    <p class="muted">Add new users or click update to edit details, role, or reset passwords.</p>
    <section class="panel">
        <h3>Registered Users List</h3>
        {user_table_html}
    </section>
  """
  return page(content)


# ---------- 8. ADMIN: EDIT SPECIFIC USER (UPDATE ROLE / PASSWORD) ----------


@app.route("/edit-user/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
      user = db.fetchone()
  finally:
    conn.close()

  if not user:
    flash("User not found.")
    return redirect(url_for("manage_users"))

  if request.method == "POST":
    updated_username = request.form.get("username", "").strip()
    updated_role = request.form.get("role", "")
    new_password = request.form.get("new_password", "").strip()

    if not updated_username or not updated_role:
      flash("Username and role are required.")
    else:
      conn = get_db()
      try:
        with conn.cursor() as db:
          db.execute("SELECT id FROM users WHERE username = %s AND id != %s", (updated_username, user_id))
          if db.fetchone():
            flash("Username already taken by another account.")
          else:
            if new_password:
              is_valid, message = validate_password(new_password)
              if not is_valid:
                flash(f"Update failed: {message}")
                return redirect(url_for("edit_user", user_id=user_id))
              hashed_pw = generate_password_hash(new_password)
              db.execute(
                  "UPDATE users SET username = %s, role = %s, password = %s WHERE id = %s",
                  (updated_username, updated_role, hashed_pw, user_id),
              )
            else:
              db.execute(
                  "UPDATE users SET username = %s, role = %s WHERE id = %s",
                  (updated_username, updated_role, user_id),
              )
            conn.commit()
            flash("User updated successfully.")
            return redirect(url_for("manage_users"))
      finally:
        conn.close()

  content = f"""
    <h2>Edit User: {user['username']}</h2>
    <section class="panel" style="max-width: 500px; margin: auto;">
    <form method="post">
        <label>Username</label>
        <input name="username" value="{user['username']}" required maxlength="100">

        <label>Role</label>
        <select name="role" required>
            <option value="protege" {'SELECTED' if user['role']=='protege' else ''}>Protege</option>
            <option value="admin" {'SELECTED' if user['role']=='admin' else ''}>Admin</option>
        </select>

        <label>New Password (Optional)</label>
        <div class="password-container">
            <input type="password" id="edit_pass" name="new_password" placeholder="Leave blank to keep current password">
            <button type="button" class="toggle-eye-btn" onclick="togglePasswordVisibility('edit_pass', this)">
                <svg viewBox="0 0 24 24"><use href="#icon-eye-open"></use></svg>
            </button>
        </div>
        <p class="muted" style="font-size: 12px; margin-top: 4px;">
            If changing password, must be at least 8 characters long and include letters, numbers, and a symbol.
        </p>

        <div style="display: flex; gap: 10px; margin-top: 20px;">
            <button type="submit" class="btn" style="margin:0;">Save Changes</button>
            <a href="/manage-users" class="btn" style="background: #66756e; text-decoration: none; text-align: center; line-height: normal; padding: 11px 18px; margin:0;">Cancel</a>
        </div>
    </form>
    </section>
  """
  return page(content)


# ---------- FILE SERVING ROUTE ----------


@app.route("/uploads/<filename>")
def uploaded_file(filename):
  return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---------- START APPLICATION ----------

if __name__ == "__main__":
  init_db()
  app.run(debug=True)
