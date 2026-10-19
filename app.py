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
.btn-warning { background: #f0ad4e; color: white; }
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

/* Modal Styles for Enlarging Data / Editing */
.modal-overlay {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0, 0, 0, 0.5); display: none; justify-content: center; align-items: center;
    z-index: 1000;
}
.modal-content {
    background: white; padding: 25px; border-radius: 12px; max-width: 500px; width: 90%;
    box-shadow: 0 5px 15px rgba(0,0,0,0.3); position: relative; max-height: 90vh; overflow-y: auto;
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

<!-- Edit Safety Report Modal -->
<div id="editSafetyModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editSafetyModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editSafetyModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Safety Report</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_safety_id" name="report_id">
            
            <label>Report Title</label>
            <input type="text" id="edit_safety_title" name="title" required maxlength="150">
            
            <label>Category</label>
            <select id="edit_safety_category" name="category" required>
                <option value="Incident">Incident</option>
                <option value="Inspection">Safety Inspection</option>
                <option value="Hazard">Hazard</option>
            </select>
            
            <label>Description</label>
            <textarea id="edit_safety_description" name="description" rows="3" maxlength="3000"></textarea>
            
            <label>Replace File (Optional)</label>
            <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editSafetyModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit Document Modal -->
<div id="editDocModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editDocModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editDocModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Document Record</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_doc_id" name="doc_id">
            
            <label>Document Title</label>
            <input type="text" id="edit_doc_title" name="title" required maxlength="150">
            
            <label>Document Type</label>
            <select id="edit_doc_type" name="doc_type" required>
                <option value="Policy">Policy</option>
                <option value="Safety Checklist">Safety Checklist</option>
                <option value="Audit Report">Audit Report</option>
                <option value="Certificate">Certificate</option>
                <option value="Other">Other</option>
            </select>
            
            <label>Next Review Date</label>
            <input type="date" id="edit_doc_review_date" name="review_date">
            
            <label>Replace File (Optional)</label>
            <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editDocModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit Training Modal -->
<div id="editTrainingModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editTrainingModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editTrainingModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Training Record</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_train_id" name="train_id">
            
            <label>Employee Name or Staff ID</label>
            <input type="text" id="edit_train_employee" name="employee" required maxlength="100">
            
            <label>Training Course</label>
            <input type="text" id="edit_train_course" name="course" required maxlength="150">
            
            <label>Certificate Expiry Date</label>
            <input type="date" id="edit_train_expiry_date" name="expiry_date">
            
            <label>Replace Certificate / File (Optional)</label>
            <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editTrainingModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit CIDB Record Modal -->
<div id="editCidbModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editCidbModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editCidbModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Protégé CIDB Record</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_cidb_id" name="record_id">
            
            <label>Document Title</label>
            <input type="text" id="edit_cidb_title" name="title" required maxlength="150">
            
            <label>Replace File (Optional)</label>
            <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editCidbModal')" style="margin-top: 15px;">Cancel</button>
        </form>
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

function closeModalOverlay(event, modalId) {
    if (event.target.id === modalId) {
        document.getElementById(modalId).style.display = 'none';
    }
}
function closeModalDirect(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

function openEditSafetyModal(id, title, category, description) {
    document.getElementById('edit_safety_id').value = id;
    document.getElementById('edit_safety_title').value = title;
    document.getElementById('edit_safety_category').value = category;
    document.getElementById('edit_safety_description').value = description;
    document.getElementById('editSafetyModal').style.display = 'flex';
}

function openEditDocModal(id, title, docType, reviewDate) {
    document.getElementById('edit_doc_id').value = id;
    document.getElementById('edit_doc_title').value = title;
    document.getElementById('edit_doc_type').value = docType;
    document.getElementById('edit_doc_review_date').value = reviewDate;
    document.getElementById('editDocModal').style.display = 'flex';
}

function openEditTrainingModal(id, employee, course, expiryDate) {
    document.getElementById('edit_train_id').value = id;
    document.getElementById('edit_train_employee').value = employee;
    document.getElementById('edit_train_course').value = course;
    document.getElementById('edit_train_expiry_date').value = expiryDate;
    document.getElementById('editTrainingModal').style.display = 'flex';
}

function openEditCidbModal(id, title) {
    document.getElementById('edit_cidb_id').value = id;
    document.getElementById('edit_cidb_title').value = title;
    document.getElementById('editCidbModal').style.display = 'flex';
}
</script>
</body>
</html>
"""


def page(content, **data):
  return render_template_string(PAGE, content=content, **data)


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
    action = request.form.get("action")
    report_id = request.form.get("report_id")

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

        elif action == "edit" and report_id:
          title = request.form.get("title", "").strip()
          category = request.form.get("category", "")
          description = request.form.get("description", "").strip()
          file = request.files.get("file")

          if title and category in ["Incident", "Inspection", "Hazard"]:
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"safety_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)
              db.execute(
                  """
                                UPDATE safety_reports 
                                SET title = %s, category = %s, description = %s, filename = %s 
                                WHERE id = %s
                            """,
                  (title, category, description, filename, report_id),
              )
            else:
              db.execute(
                  """
                                UPDATE safety_reports 
                                SET title = %s, category = %s, description = %s 
                                WHERE id = %s
                            """,
                  (title, category, description, report_id),
              )

        else:
          title = request.form.get("title", "").strip()
          category = request.form.get("category", "")
          description = request.form.get("description", "").strip()
          file = request.files.get("file")

          if title and category in ["Incident", "Inspection", "Hazard"]:
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
    escaped_title = r["title"].replace("'", "\\'")
    escaped_category = r["category"].replace("'", "\\'")
    escaped_desc = (r["description"] or "").replace("'", "\\'").replace("\n", " ")

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
                <button type="button" class="btn btn-warning btn-sm" onclick="openEditSafetyModal('{r['id']}', '{escaped_title}', '{escaped_category}', '{escaped_desc}')">Edit</button>
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
        elif action == "edit" and doc_id:
          title = request.form.get("title", "").strip()
          doc_type = request.form.get("doc_type", "").strip()
          review_date = request.form.get("review_date", "")

          if title and doc_type:
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"doc_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)
              db.execute(
                  """
                                UPDATE documents 
                                SET title = %s, doc_type = %s, review_date = %s, filename = %s 
                                WHERE id = %s
                            """,
                  (title, doc_type, review_date or None, filename, doc_id),
              )
            else:
              db.execute(
                  """
                                UPDATE documents 
                                SET title = %s, doc_type = %s, review_date = %s 
                                WHERE id = %s
                            """,
                  (title, doc_type, review_date or None, doc_id),
              )
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
      " Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = (
        f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
        if r["filename"]
        else "-"
    )
    escaped_title = r["title"].replace("'", "\\'")
    r_date = r["review_date"] or ""

    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td>{r['doc_type']}</td>
            <td>{file_link}</td>
            <td>{r['review_date'] or '-'}</td>
            <td>
                <button type="button" class="btn btn-warning btn-sm" onclick="openEditDocModal('{r['id']}', '{escaped_title}', '{r['doc_type']}', '{r_date}')">Edit</button>
                <form method="post" onsubmit="return confirm('Delete this document?');" style="display:inline;">
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
        elif action == "edit" and train_id:
          employee = request.form.get("employee", "").strip()
          course = request.form.get("course", "").strip()
          expiry_date = request.form.get("expiry_date", "")

          if employee and course:
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"train_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)
              db.execute(
                  """
                                UPDATE training 
                                SET employee = %s, course = %s, expiry_date = %s, filename = %s 
                                WHERE id = %s
                            """,
                  (employee, course, expiry_date or None, filename, train_id),
              )
            else:
              db.execute(
                  """
                                UPDATE training 
                                SET employee = %s, course = %s, expiry_date = %s 
                                WHERE id = %s
                            """,
                  (employee, course, expiry_date or None, train_id),
              )
        else:
          employee = request.form.get("employee", "").strip()
          course = request.form.get("course", "").strip()
          expiry_date = request.form.get("expiry_date", "")
          if employee and course:
            filename = None
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"train_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)

            db.execute(
                """
                            INSERT INTO training (employee, course, filename, expiry_date)
                            VALUES (%s, %s, %s, %s)
                        """,
                (employee, course, filename, expiry_date or None),
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
      " Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = (
        f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
        if r["filename"]
        else "-"
    )
    escaped_emp = r["employee"].replace("'", "\\'")
    escaped_crs = r["course"].replace("'", "\\'")
    e_date = r["expiry_date"] or ""

    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['employee']}</td>
            <td>{r['course']}</td>
            <td>{file_link}</td>
            <td>{r['expiry_date'] or '-'}</td>
            <td>
                <button type="button" class="btn btn-warning btn-sm" onclick="openEditTrainingModal('{r['id']}', '{escaped_emp}', '{escaped_crs}', '{e_date}')">Edit</button>
                <form method="post" onsubmit="return confirm('Delete this record?');" style="display:inline;">
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


# ---------- 5. PROTÉGÉ CIDB RECORDS (Protege / Admin) ----------


@app.route("/my-cidb", methods=["GET", "POST"])
def my_cidb():
  if "user_id" not in session:
    return redirect(url_for("login"))

  user_id = session["user_id"]
  role = session["role"]

  if request.method == "POST":
    action = request.form.get("action")
    record_id = request.form.get("record_id")
    file = request.files.get("file")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "delete" and record_id:
          if role == "admin":
            db.execute("SELECT filename FROM cidb_uploads WHERE id = %s", (record_id,))
          else:
            db.execute(
                "SELECT filename FROM cidb_uploads WHERE id = %s AND user_id = %s",
                (record_id, user_id),
            )
          row = db.fetchone()
          if row and row["filename"]:
            f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if f_path.exists():
              os.remove(f_path)

          if role == "admin":
            db.execute("DELETE FROM cidb_uploads WHERE id = %s", (record_id,))
          else:
            db.execute(
                "DELETE FROM cidb_uploads WHERE id = %s AND user_id = %s",
                (record_id, user_id),
            )
        elif action == "edit" and record_id:
          title = request.form.get("title", "").strip()
          if title:
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"cidb_{session['username']}_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)
              if role == "admin":
                db.execute(
                    "UPDATE cidb_uploads SET title = %s, filename = %s WHERE id = %s",
                    (title, filename, record_id),
                )
              else:
                db.execute(
                    "UPDATE cidb_uploads SET title = %s, filename = %s WHERE id = %s AND user_id = %s",
                    (title, filename, record_id, user_id),
                )
            else:
              if role == "admin":
                db.execute(
                    "UPDATE cidb_uploads SET title = %s WHERE id = %s",
                    (title, record_id),
                )
              else:
                db.execute(
                    "UPDATE cidb_uploads SET title = %s WHERE id = %s AND user_id = %s",
                    (title, record_id, user_id),
                )
        else:
          title = request.form.get("title", "").strip()
          if title and file and file.filename and allowed_file(file.filename):
            filename = secure_filename(
                f"cidb_{session['username']}_{date.today().isoformat()}_{file.filename}"
            )
            file.save(app.config["UPLOAD_FOLDER"] / filename)

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

    return redirect(url_for("my_cidb" if role != "admin" else "manage_cidb"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute(
          """
                SELECT id, title, filename, uploaded_at 
                FROM cidb_uploads WHERE user_id = %s ORDER BY id DESC
            """,
          (user_id,),
      )
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>File</th><th>Uploaded"
      " Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
    escaped_title = r["title"].replace("'", "\\'")
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td>{file_link}</td>
            <td>{r['uploaded_at']}</td>
            <td>
                <button type="button" class="btn btn-warning btn-sm" onclick="openEditCidbModal('{r['id']}', '{escaped_title}')">Edit</button>
                <form method="post" onsubmit="return confirm('Delete this record?');" style="display:inline;">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="record_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>My CIDB & Protégé Documents</h2>
    <section class="panel">
    <h3>Upload New Document / CIDB Card</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Document Title</label>
        <input name="title" required maxlength="150" placeholder="e.g., Green Card CIDB, CV, Certificate">
        <label>Attach File (PDF, JPG, PNG)</label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf" required>
        <button type="submit">Upload Document</button>
    </form>
    </section>
    <section class="panel"><h3>My Uploaded Records</h3>
    {table_html}
    </section>
    """
  return page(content)


@app.route("/manage-cidb", methods=["GET", "POST"])
def manage_cidb():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    action = request.form.get("action")
    record_id = request.form.get("record_id")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "delete" and record_id:
          db.execute("SELECT filename FROM cidb_uploads WHERE id = %s", (record_id,))
          row = db.fetchone()
          if row and row["filename"]:
            f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
            if f_path.exists():
              os.remove(f_path)
          db.execute("DELETE FROM cidb_uploads WHERE id = %s", (record_id,))
        elif action == "edit" and record_id:
          title = request.form.get("title", "").strip()
          file = request.files.get("file")
          if title:
            if file and file.filename and allowed_file(file.filename):
              filename = secure_filename(
                  f"cidb_admin_{date.today().isoformat()}_{file.filename}"
              )
              file.save(app.config["UPLOAD_FOLDER"] / filename)
              db.execute(
                  "UPDATE cidb_uploads SET title = %s, filename = %s WHERE id = %s",
                  (title, filename, record_id),
              )
            else:
              db.execute(
                  "UPDATE cidb_uploads SET title = %s WHERE id = %s",
                  (title, record_id),
              )
      conn.commit()
    finally:
      conn.close()
    return redirect(url_for("manage_cidb"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("""
                SELECT c.id, u.username, c.title, c.filename, c.uploaded_at 
                FROM cidb_uploads c JOIN users u ON c.user_id = u.id 
                ORDER BY c.id DESC
            """)
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Protégé"
      " Username</th><th>Title</th><th>File</th><th>Uploaded"
      " Date</th><th>Actions</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
    escaped_title = r["title"].replace("'", "\\'")
    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td><strong>{r['username']}</strong></td>
            <td>{r['title']}</td>
            <td>{file_link}</td>
            <td>{r['uploaded_at']}</td>
            <td>
                <button type="button" class="btn btn-warning btn-sm" onclick="openEditCidbModal('{r['id']}', '{escaped_title}')">Edit</button>
                <form method="post" onsubmit="return confirm('Delete this record?');" style="display:inline;">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="record_id" value="{r['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>All Protégé CIDB Records & Documents</h2>
    <section class="panel"><h3>Monitor All Uploads</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- 6. MANAGE USERS & PASSWORDS (Admin Only) ----------


@app.route("/manage-users", methods=["GET", "POST"])
def manage_users():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))

  if request.method == "POST":
    action = request.form.get("action")
    user_id = request.form.get("user_id")

    conn = get_db()
    try:
      with conn.cursor() as db:
        if action == "delete" and user_id:
          if int(user_id) == session.get("user_id"):
            flash("You cannot delete your own admin account while logged in.")
          else:
            db.execute("DELETE FROM users WHERE id = %s", (user_id,))
        elif action == "update_password" and user_id:
          new_pass = request.form.get("new_password", "")
          is_valid, message = validate_password(new_pass)
          if not is_valid:
            flash(message)
          else:
            hashed = generate_password_hash(new_pass)
            db.execute(
                "UPDATE users SET password = %s WHERE id = %s", (hashed, user_id)
            )
            flash("User password updated successfully.")
      conn.commit()
    finally:
      conn.close()
    return redirect(url_for("manage-users"))

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT id, username, role FROM users ORDER BY id ASC")
      users = db.fetchall()
  finally:
    conn.close()

  users_table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Username</th><th>Role</th><th>Update"
      " Password</th><th>Action</th></tr></thead><tbody>"
  )
  for u in users:
    users_table_html += f"""
        <tr>
            <td>{u['id']}</td>
            <td><strong>{u['username']}</strong></td>
            <td>{u['role']|capitalize}</td>
            <td>
                <form method="post" style="display:flex; gap:6px;">
                    <input type="hidden" name="action" value="update_password">
                    <input type="hidden" name="user_id" value="{u['id']}">
                    <div class="password-container" style="flex:1;">
                        <input type="password" id="pass_{u['id']}" name="new_password" placeholder="New Password" required style="margin-top:0; padding:6px;">
                        <button type="button" class="toggle-eye-btn" onclick="togglePasswordVisibility('pass_{u['id']}', this)">
                            <svg viewBox="0 0 24 24"><use href="#icon-eye-open"></use></svg>
                        </button>
                    </div>
                    <button type="submit" class="btn btn-sm" style="margin-top:0;">Update</button>
                </form>
            </td>
            <td>
                <form method="post" onsubmit="return confirm('Delete user {u["username"]}?');">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="user_id" value="{u['id']}">
                    <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                </form>
            </td>
        </tr>
        """
  users_table_html += "</tbody></table></div>"

  content = f"""
    <h2>Manage Users & Passwords</h2>
    <section class="panel">
        <h3>System User Accounts</h3>
        <p class="muted" style="font-size: 13px; margin-top:-5px; margin-bottom:12px;">Admin can reset user passwords or remove user accounts.</p>
        {users_table_html}
    </section>
    """
  return page(content)


# ---------- STATIC FILE SERVING ----------


@app.route("/uploads/<filename>")
def uploaded_file(filename):
  return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


if __name__ == "__main__":
  init_db()
  app.run(debug=True, port=5000)
