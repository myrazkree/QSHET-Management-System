# QSHET Management System - Improved Version
# Built additively from qshetms(4).py. Existing modules, routes, role names,
# database tables, and user workflows are intentionally retained.
# Review deployment environment variables before running in production.

from datetime import date, datetime, timedelta
import os
import secrets
import uuid
from pathlib import Path
from urllib.parse import quote
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
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT_" + secrets.token_hex(16))
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB maximum upload

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
    "host": os.environ.get("DB_HOST", "localhost"),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD", ""),
    "database": os.environ.get("DB_NAME", "qshet_db"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "connect_timeout": 10,
    "read_timeout": 30,
    "write_timeout": 30,
    "autocommit": False,
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
                    role VARCHAR(20) NOT NULL,
                    must_change_password TINYINT(1) NOT NULL DEFAULT 0
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

      # CIDB / User Document Uploads table
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

      # Employees / Staff table
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NULL UNIQUE,
          full_name VARCHAR(150) NOT NULL,
          staff_id VARCHAR(80) NULL,
          department VARCHAR(100) NULL,
          position VARCHAR(100) NULL,
          cidb_number VARCHAR(100) NULL,
          cidb_expiry DATE NULL,
          employment_status VARCHAR(30) NOT NULL DEFAULT 'Active',
          filename VARCHAR(255) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT fk_employee_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB;
      """)

      # Corrective actions table
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS corrective_actions (
          id INT AUTO_INCREMENT PRIMARY KEY,
          title VARCHAR(180) NOT NULL,
          description TEXT,
          source_type VARCHAR(50) NOT NULL DEFAULT 'General',
          source_id INT NULL,
          location VARCHAR(180) NULL,
          severity VARCHAR(30) NOT NULL DEFAULT 'Medium',
          assigned_to VARCHAR(150) NULL,
          due_date DATE NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'Open',
          resolution_notes TEXT,
          filename VARCHAR(255) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          resolved_at DATETIME NULL
        ) ENGINE=InnoDB;
      """)

      # Inspections table
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS inspections (
          id INT AUTO_INCREMENT PRIMARY KEY,
          site_name VARCHAR(180) NOT NULL,
          inspection_date DATE NOT NULL,
          inspector VARCHAR(150) NOT NULL,
          checklist_item VARCHAR(180) NOT NULL,
          result VARCHAR(30) NOT NULL DEFAULT 'Pass',
          findings TEXT,
          corrective_action TEXT,
          assigned_to VARCHAR(150) NULL,
          due_date DATE NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'Open',
          filename VARCHAR(255) NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
      """)

      # Audit logs table
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NULL,
          username VARCHAR(100) NULL,
          action VARCHAR(100) NOT NULL,
          details TEXT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_audit_created (created_at)
        ) ENGINE=InnoDB;
      """)

      # Tasks assigned by an administrator (for Protégés and Staff)
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS protege_tasks (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          title VARCHAR(180) NOT NULL,
          description TEXT NULL,
          priority VARCHAR(20) NOT NULL DEFAULT 'Normal',
          due_date DATE NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'To Do',
          completion_note TEXT NULL,
          created_by INT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          completed_at DATETIME NULL,
          CONSTRAINT fk_task_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
          CONSTRAINT fk_task_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB;
      """)

      # Work diary / weekly activity log (for Protégés and Staff)
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS protege_work_logs (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          activity_date DATE NOT NULL,
          activity_title VARCHAR(180) NOT NULL,
          description TEXT NULL,
          skills_learned TEXT NULL,
          challenges TEXT NULL,
          hours_spent DECIMAL(5,2) NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'Submitted',
          supervisor_feedback TEXT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT fk_worklog_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB;
      """)

      # Safety submissions made by Users, separate from admin-managed safety records
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS protege_safety_submissions (
          id INT AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          title VARCHAR(150) NOT NULL,
          category VARCHAR(50) NOT NULL,
          location VARCHAR(180) NULL,
          description TEXT NOT NULL,
          filename VARCHAR(255) NULL,
          status VARCHAR(30) NOT NULL DEFAULT 'Submitted',
          admin_response TEXT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT fk_safety_submit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB;
      """)

      # Company announcements and reminders
      cursor.execute("""
        CREATE TABLE IF NOT EXISTS protege_announcements (
          id INT AUTO_INCREMENT PRIMARY KEY,
          title VARCHAR(180) NOT NULL,
          body TEXT NOT NULL,
          announcement_type VARCHAR(40) NOT NULL DEFAULT 'General',
          due_date DATE NULL,
          created_by INT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          CONSTRAINT fk_announcement_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB;
      """)

      # Add review metadata to document uploads
      for col, definition in [
          ("review_status", "VARCHAR(30) NOT NULL DEFAULT 'Pending'"),
          ("review_note", "TEXT NULL"),
          ("reviewed_at", "DATETIME NULL"),
      ]:
        cursor.execute(f"SHOW COLUMNS FROM cidb_uploads LIKE '{col}'")
        if not cursor.fetchone():
          cursor.execute(f"ALTER TABLE cidb_uploads ADD COLUMN {col} {definition}")

      # Auto-patch existing tables if filename column is missing
      for tbl in ["safety_reports", "documents", "training", "employees", "corrective_actions", "inspections"]:
        cursor.execute(f"SHOW COLUMNS FROM {tbl} LIKE 'filename'")
        if not cursor.fetchone():
          cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN filename VARCHAR(255) NULL")

      # Migrate existing installations for must_change_password
      cursor.execute("SHOW COLUMNS FROM users LIKE 'must_change_password'")
      if not cursor.fetchone():
        cursor.execute("ALTER TABLE users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0")

      # Seed a first admin only when the users table is empty.
      cursor.execute("SELECT COUNT(*) AS cnt FROM users")
      if cursor.fetchone()["cnt"] == 0:
        admin_pass = generate_password_hash(os.environ.get("INITIAL_ADMIN_PASSWORD", "Admin@123"))
        cursor.execute(
            "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, 'admin', 1)",
            (os.environ.get("INITIAL_ADMIN_USERNAME", "admin"), admin_pass),
        )

      # Additive indexes for common departmental lookups. Existing records and
      # table structures are preserved.
      index_specs = {
          "idx_safety_status_created": ("safety_reports", "status, created_at"),
          "idx_documents_review_date": ("documents", "review_date"),
          "idx_training_expiry_date": ("training", "expiry_date"),
          "idx_cidb_user": ("cidb_uploads", "user_id"),
          "idx_actions_status_due": ("corrective_actions", "status, due_date"),
          "idx_actions_source": ("corrective_actions", "source_type, source_id"),
          "idx_inspections_result_due": ("inspections", "result, due_date"),
          "idx_tasks_user_status_due": ("protege_tasks", "user_id, status, due_date"),
          "idx_worklogs_user_date": ("protege_work_logs", "user_id, activity_date"),
      }
      for index_name, (table_name, columns) in index_specs.items():
        cursor.execute(f"SHOW INDEX FROM `{table_name}` WHERE Key_name = %s", (index_name,))
        if not cursor.fetchone():
          cursor.execute(f"CREATE INDEX `{index_name}` ON `{table_name}` ({columns})")

    conn.commit()
  except Exception:
    conn.rollback()
    app.logger.exception("Database initialisation or additive index check failed")
    raise
  finally:
    conn.close()


def log_action(action, details=""):
  """Record an auditable action with request context, preserving the existing schema."""
  try:
    metadata = []
    if request:
      metadata.extend([
          f"route={request.endpoint or 'unknown'}",
          f"method={request.method}",
          f"ip={request.remote_addr or 'unknown'}",
      ])
    if details:
      metadata.append(str(details))
    
    audit_details = " — ".join(metadata)[:4000]
    
    conn = get_db()
    try:
      with conn.cursor() as db:
        db.execute(
          "INSERT INTO audit_logs (user_id, username, action, details) VALUES (%s, %s, %s, %s)",
          (session.get("user_id"), session.get("username"), str(action)[:100], audit_details),
        )
      conn.commit()
    except Exception:
      conn.rollback()
      raise
    finally:
      conn.close()
  except Exception:
    app.logger.exception("Could not write audit log for action %s", action)


def save_upload(file, prefix="file"):
  """Validate extension and assign a unique, non-user-controlled storage name."""
  if not file or not file.filename:
    return None
  if not valid_upload_file(file):
    raise ValueError("Only PDF, JPG, JPEG and PNG files are allowed.")
  original = secure_filename(file.filename)
  suffix = Path(original).suffix.lower()
  filename = f"{prefix}_{uuid.uuid4().hex}{suffix}"
  file.save(app.config["UPLOAD_FOLDER"] / filename)
  return filename


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
    background: #f8f6f0; color: #2d3732;
    display: flex; flex-direction: column; min-height: 100vh;
}
header {
    background: #2d4a3e; color: #f4efe6;
    padding: 22px 5%;
    display: flex; justify-content: space-between; align-items: center;
}
header h1 { margin: 0 0 6px; font-size: 24px; }
header p { margin: 0; color: #c2d4cb; }
.user-info { text-align: right; font-size: 14px; }
.user-info a { color: #e8c580; text-decoration: none; font-weight: bold; }
nav {
    background: #ffffff; 
    padding: 14px 5%;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
    gap: 18px;
    border-bottom: 1px solid #e8e3d8;
    align-items: center;
}
nav a { 
    color: #3b6251; 
    text-decoration: none; 
    font-weight: bold;
    text-align: center;
}
nav a:hover {
    color: #e8c580;
    text-decoration: underline;
}
nav a:active {
    color: #183b35;
}
main { max-width: 1100px; margin: 28px auto; padding: 0 18px; flex: 1; }
.cards {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px;
}
.card {
    background: #ffffff; padding: 20px;
    border-radius: 12px; margin-bottom: 18px;
    box-shadow: 0 4px 16px rgba(45, 74, 62, 0.05);
    border: 1px solid #eef2f0;
    text-decoration: none; color: inherit; display: block;
    transition: transform 0.25s ease, box-shadow 0.25s ease;
}
.card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 24px rgba(45, 74, 62, 0.1);
}
.panel {
    background: #ffffff; padding: 20px;
    border-radius: 12px; margin-bottom: 18px;
    box-shadow: 0 4px 16px rgba(45, 74, 62, 0.05);
    border: 1px solid #eef2f0;
    overflow: visible !important;
}
.number { font-size: 30px; font-weight: bold; color: #3b6251; }
label { display: block; margin-top: 12px; font-weight: bold; color: #43544c; }
input, select, textarea {
    width: 100%; padding: 10px; margin-top: 6px;
    border: 1px solid #d8e0dc; border-radius: 8px;
    background: #fafaf8; color: #2d3732;
}
button, .btn {
    background: #3b6251; color: #f8f6f0; border: 0;
    padding: 11px 18px; margin-top: 14px;
    border-radius: 8px; cursor: pointer; text-decoration: none; display: inline-block;
    font-weight: 600;
}
button:hover, .btn:hover { background: #2d4a3e; }
.btn-danger { background: #c85a54; }
.btn-warning { background: #dfa85b; color: #2d3732; }
.btn-sm { padding: 6px 12px; margin-top: 4px; font-size: 12px; }
table { width: 100%; border-collapse: collapse; background: #ffffff; }
th, td { padding: 11px; border-bottom: 1px solid #ebece8; text-align: left; }
.clickable-row { cursor: pointer; transition: background 0.2s; }
.clickable-row:hover { background: #f0f4f2; }
.table-wrap { width: 100%; overflow-x: auto; overflow-y: visible !important; }
.badge { background: #e3ece8; color: #2d4a3e; padding: 5px 8px; border-radius: 20px; font-weight: 600; }
.muted { color: #7a8c83; }
.alert { background: #fbf0ee; color: #8a332d; padding: 12px 16px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid #c85a54; }
footer {
    background: #1e382c; color: #b0c4ba; text-align: center;
    padding: 16px 5%; margin-top: 40px; font-size: 13px;
    border-top: 3px solid #2d4a3e;
}
footer strong { color: #e8c580; }
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
    display: flex; align-items: center; justify-content: center; color: #7a8c83;
}
.toggle-eye-btn svg {
    width: 22px; height: 22px; stroke: currentColor;
    stroke-width: 2; fill: none; stroke-linecap: round; stroke-linejoin: round;
}
.strength-meter { margin-top: 6px; font-size: 13px; font-weight: bold; }
.text-weak { color: #c85a54; }
.text-moderate { color: #dfa85b; }
.text-strong { color: #52826e; }
.action-menu-container {
    position: relative;
    display: inline-block;
}
.action-dots-btn {
    background: #ffffff;
    border: 1px solid #d8e0dc;
    border-radius: 8px;
    padding: 6px 10px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #2d3732;
    box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    transition: background 0.2s;
}
.action-dots-btn:hover {
    background: #f0f4f2;
}
.action-dots-btn svg {
    width: 18px;
    height: 18px;
    fill: currentColor;
}
.action-dropdown {
    display: none;
    position: absolute;
    right: 0;
    top: 100%;
    margin-top: 4px;
    background: #ffffff;
    min-width: 140px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.12);
    border: 1px solid #ebece8;
    border-radius: 10px;
    z-index: 999;
    overflow: hidden;
}
.action-dropdown.show {
    display: block;
}
.action-dropdown a, .action-dropdown button {
    display: flex;
    align-items: center;
    gap: 8px;
    width: 100%;
    padding: 10px 14px;
    text-align: left;
    background: none;
    border: none;
    color: #2d3732;
    font-size: 13px;
    font-weight: 500;
    text-decoration: none;
    cursor: pointer;
    margin: 0;
}
.action-dropdown a:hover, .action-dropdown button:hover {
    background: #f0f4f2;
    color: #183b35;
}
.action-dropdown button.text-danger, .action-dropdown a.text-danger {
    color: #c85a54;
}
.action-dropdown button.text-danger:hover, .action-dropdown a.text-danger:hover {
    background: #fbf0ee;
}
.modal-overlay {
    position: fixed; top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(30, 56, 44, 0.4); display: none; justify-content: center; align-items: center;
    z-index: 1000; backdrop-filter: blur(4px);
}
.modal-content {
    background: #ffffff; padding: 25px; border-radius: 16px; max-width: 500px; width: 90%;
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.12); position: relative; max-height: 90vh; overflow-y: auto;
    border: 1px solid #ebece8;
}
.modal-close {
    position: absolute; top: 12px; right: 16px; font-size: 22px; cursor: pointer; color: #7a8c83;
    font-weight: bold;
}
.modal-field { margin-bottom: 12px; }
.modal-field label { font-weight: bold; color: #2d4a3e; margin-bottom: 2px; }
.modal-field div { background: #f8f6f0; padding: 8px 12px; border-radius: 8px; border: 1px solid #e8e3d8; }
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
            Logged in as: <strong>{{ session.get('username') }}</strong> ({{ session.get('role').capitalize() }})<br>
            <a href="/logout">Logout</a>
        {% else %}
            <a href="/login">Login</a>
        {% endif %}
    </div>
</header>
<nav>
    <a href="/">Dashboard</a> 
    {% if session.get('role') == 'admin' %}
        <a href="/safety">Safety Reports</a>  
        <a href="/documents">Document Records</a>  
        <a href="/training">Training & Compliance</a>  
        <a href="/manage-cidb">All User CIDB Records</a>  
        <a href="/manage-users">Manage Users & Passwords</a>  
        <a href="/employees">Staff & Protégé Profiles</a>  
        <a href="/actions">Corrective Actions</a>  
        <a href="/inspections">Site Inspections</a>  
        <a href="/reports">Reports & Audit Log</a>  
        <a href="/alerts">QSHET Alerts </a>  
        <a href="/tasks">Tasks</a>  
        <a href="/work-log">Work Logs</a>  
        <a href="/submit-safety">Safety Inbox</a>  
        <a href="/announcements">Announcements</a>
    {% elif session.get('role') == 'protege' or session.get('role') == 'staff' %}
        <a href="/my-profile">My Profile</a>  
        <a href="/my-tasks">My Tasks</a>  
        <a href="/my-training">My Training</a>  
        <a href="/work-log">My Work Log</a>  
        <a href="/submit-safety">Submit Safety Report</a>  
        <a href="/announcements">Announcements</a>  
        <a href="/my-cidb">My Documents</a> 
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
        <span class="modal-close" onclick="closeDetailModal()">&times;</span>
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
            
            <label>Replace Certificate / File (Optional)</label>
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
            
            <label>Replace Certificate / File (Optional)</label>
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
        <h3 style="margin-top:0; color:#183b35;">Edit User CIDB Record</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_cidb_id" name="record_id">
            
            <label>Document Title</label>
            <input type="text" id="edit_cidb_title" name="title" required maxlength="150">
            
            <label>Replace Certificate / File (Optional)</label>
            <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editCidbModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit Task Modal -->
<div id="editTaskModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editTaskModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editTaskModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Assigned Task</h3>
        <form method="POST">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_task_id" name="task_id">
            
            <label>User / Assignee</label>
            <select id="edit_task_user_id" name="user_id" required>
                <!-- populated dynamically -->
            </select>
            
            <label>Task Title</label>
            <input type="text" id="edit_task_title" name="title" required maxlength="180">
            
            <label>Description / Expected Output</label>
            <textarea id="edit_task_description" name="description" rows="3"></textarea>
            
            <label>Priority</label>
            <select id="edit_task_priority" name="priority">
                <option value="Low">Low</option>
                <option value="Normal">Normal</option>
                <option value="High">High</option>
                <option value="Urgent">Urgent</option>
            </select>
            
            <label>Due Date</label>
            <input type="date" id="edit_task_due_date" name="due_date">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editTaskModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit Announcement Modal -->
<div id="editAnnouncementModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editAnnouncementModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editAnnouncementModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Announcement</h3>
        <form method="POST">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_ann_id" name="announcement_id">
            
            <label>Title</label>
            <input type="text" id="edit_ann_title" name="title" required maxlength="180">
            
            <label>Details</label>
            <textarea id="edit_ann_body" name="body" rows="4" required></textarea>
            
            <label>Type</label>
            <select id="edit_ann_type" name="announcement_type">
                <option value="General">General</option>
                <option value="Training">Training</option>
                <option value="Safety Briefing">Safety Briefing</option>
                <option value="Deadline">Deadline</option>
                <option value="Meeting">Meeting</option>
                <option value="Site Notice">Site Notice</option>
            </select>
            
            <label>Deadline (optional)</label>
            <input type="date" id="edit_ann_due_date" name="due_date">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editAnnouncementModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit Work Log Modal -->
<div id="editWorkLogModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editWorkLogModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editWorkLogModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Work Log</h3>
        <form method="POST">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_log_id" name="log_id">
            
            <label>Activity Date</label>
            <input type="date" id="edit_log_date" name="activity_date" required>
            
            <label>Activity / Task Title</label>
            <input type="text" id="edit_log_title" name="activity_title" required maxlength="180">
            
            <label>What did you do?</label>
            <textarea id="edit_log_desc" name="description" rows="3"></textarea>
            
            <label>Skills or knowledge learned</label>
            <textarea id="edit_log_skills" name="skills_learned" rows="2"></textarea>
            
            <label>Challenges / follow-up needed</label>
            <textarea id="edit_log_challenges" name="challenges" rows="2"></textarea>
            
            <label>Hours spent (optional)</label>
            <input type="number" id="edit_log_hours" name="hours_spent" min="0" max="24" step="0.25">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editWorkLogModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- Edit Safety Submission Modal -->
<div id="editSafetySubModal" class="modal-overlay" onclick="closeModalOverlay(event, 'editSafetySubModal')">
    <div class="modal-content" onclick="event.stopPropagation()">
        <span class="modal-close" onclick="closeModalDirect('editSafetySubModal')">&times;</span>
        <h3 style="margin-top:0; color:#183b35;">Edit Safety Submission</h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" id="edit_sub_id" name="submission_id">
            
            <label>Title</label>
            <input type="text" id="edit_sub_title" name="title" required maxlength="150">
            
            <label>Category</label>
            <select id="edit_sub_category" name="category" required>
                <option value="Hazard">Hazard</option>
                <option value="Near Miss">Near Miss</option>
                <option value="Unsafe Act">Unsafe Act</option>
                <option value="Unsafe Condition">Unsafe Condition</option>
                <option value="Environmental">Environmental</option>
                <option value="Traffic">Traffic</option>
                <option value="Other">Other</option>
            </select>
            
            <label>Location / site</label>
            <input type="text" id="edit_sub_location" name="location" maxlength="180">
            
            <label>Description</label>
            <textarea id="edit_sub_description" name="description" rows="4" required></textarea>
            
            <label>Replace photo / document (optional)</label>
            <input type="file" name="file" accept=".pdf,.png,.jpg,.jpeg">
            
            <button type="submit" class="btn" style="margin-top: 15px;">Save Changes</button>
            <button type="button" class="btn btn-danger" onclick="closeModalDirect('editSafetySubModal')" style="margin-top: 15px;">Cancel</button>
        </form>
    </div>
</div>

<!-- SVG Icon Definitions -->
<svg style="display:none;">
  <g id="icon-eye-open">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
    <circle cx="12" cy="12" r="3"></circle>
  </g>
  <g id="icon-eye-off">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
    <line x1="1" y1="1" x2="23" y2="23"></line>
  </g>
  <g id="icon-three-dots">
    <circle cx="12" cy="5" r="2"></circle>
    <circle cx="12" cy="12" r="2"></circle>
    <circle cx="12" cy="19" r="2"></circle>
  </g>
  <g id="icon-edit-pencil">
    <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
    <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
  </g>
  <g id="icon-trash">
    <polyline points="3 6 5 6 21 6"></polyline>
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
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

function toggleActionMenu(event, menuId) {
    event.stopPropagation();
    document.querySelectorAll('.action-dropdown').forEach(menu => {
        if (menu.id !== menuId) menu.classList.remove('show');
    });
    const menu = document.getElementById(menuId);
    if (menu) {
        menu.classList.toggle('show');
    }
}

window.addEventListener('click', function() {
    document.querySelectorAll('.action-dropdown').forEach(menu => {
        menu.classList.remove('show');
    });
});

function showReportDetails(id, title, category, description, filename, status, created_at) {
    const modalBody = document.getElementById('modalBody');
    modalBody.replaceChildren();

    function addField(labelText, value) {
        const wrapper = document.createElement('div');
        wrapper.className = 'modal-field';
        const label = document.createElement('label');
        label.textContent = labelText;
        const valueBox = document.createElement('div');
        valueBox.textContent = value == null || value === '' ? '—' : String(value);
        wrapper.append(label, valueBox);
        modalBody.appendChild(wrapper);
    }

    addField('Report ID', id);
    addField('Title', title);
    addField('Category', category);
    addField('Description', description || 'No description provided');

    const fileWrapper = document.createElement('div');
    fileWrapper.className = 'modal-field';
    const fileLabel = document.createElement('label');
    fileLabel.textContent = 'Attached File';
    const fileBox = document.createElement('div');
    if (filename) {
        const link = document.createElement('a');
        link.href = '/uploads/' + encodeURIComponent(String(filename));
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = 'View attached file';
        fileBox.appendChild(link);
    } else {
        fileBox.textContent = 'None';
    }
    fileWrapper.append(fileLabel, fileBox);
    modalBody.appendChild(fileWrapper);

    addField('Status', status);
    addField('Created Date', created_at);
    document.getElementById('detailModal').style.display = 'flex';
}

function closeModal(event) {
    if (event.target.id === 'detailModal') {
        document.getElementById('detailModal').style.display = 'none';
    }
}
function closeDetailModal() {
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

function openEditTaskModal(id, userId, title, description, priority, dueDate) {
    document.getElementById('edit_task_id').value = id;
    document.getElementById('edit_task_title').value = title;
    document.getElementById('edit_task_description').value = description;
    document.getElementById('edit_task_priority').value = priority;
    document.getElementById('edit_task_due_date').value = dueDate;
    
    const mainSelect = document.querySelector('select[name="user_id"]');
    const editSelect = document.getElementById('edit_task_user_id');
    if (mainSelect && editSelect) {
        editSelect.innerHTML = mainSelect.innerHTML;
        editSelect.value = userId;
    }
    document.getElementById('editTaskModal').style.display = 'flex';
}

function openEditAnnouncementModal(id, title, body, annType, dueDate) {
    document.getElementById('edit_ann_id').value = id;
    document.getElementById('edit_ann_title').value = title;
    document.getElementById('edit_ann_body').value = body;
    document.getElementById('edit_ann_type').value = annType;
    document.getElementById('edit_ann_due_date').value = dueDate;
    document.getElementById('editAnnouncementModal').style.display = 'flex';
}

function openEditWorkLogModal(id, activityDate, title, description, skills, challenges, hours) {
    document.getElementById('edit_log_id').value = id;
    document.getElementById('edit_log_date').value = activityDate;
    document.getElementById('edit_log_title').value = title;
    document.getElementById('edit_log_desc').value = description;
    document.getElementById('edit_log_skills').value = skills;
    document.getElementById('edit_log_challenges').value = challenges;
    document.getElementById('edit_log_hours').value = hours;
    document.getElementById('editWorkLogModal').style.display = 'flex';
}

function openEditSafetySubModal(id, title, category, location, description) {
    document.getElementById('edit_sub_id').value = id;
    document.getElementById('edit_sub_title').value = title;
    document.getElementById('edit_sub_category').value = category;
    document.getElementById('edit_sub_location').value = location;
    document.getElementById('edit_sub_description').value = description;
    document.getElementById('editSafetySubModal').style.display = 'flex';
}

document.addEventListener('DOMContentLoaded', function() {
    const filterSelect = document.querySelector('select[name="filter"]');
    if (filterSelect) {
        filterSelect.addEventListener('change', function() {
            const customDatesDiv = document.getElementById('custom_dates');
            if (customDatesDiv) {
                customDatesDiv.style.display = (this.value === 'custom') ? 'flex' : 'none';
            }
        });
    }
});
</script>
</body>
</html>
"""


def page(content, **data):
  return render_template_string(PAGE, content=content, **data)


def action_menu_html(menu_id, items_html):
  return f"""
  <div class="action-menu-container">
      <button type="button" class="action-dots-btn" onclick="toggleActionMenu(event, '{menu_id}')">
          <svg viewBox="0 0 24 24"><use href="#icon-three-dots"></use></svg>
      </button>
      <div id="{menu_id}" class="action-dropdown">
          {items_html}
      </div>
  </div>
  """


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
      session.clear()
      session["user_id"] = user["id"]
      session["username"] = user["username"]
      session["role"] = user["role"]
      session["must_change_password"] = bool(user.get("must_change_password", 0))
      log_action("login", "Successful login")
      if session["must_change_password"]:
        return redirect(url_for("change_password"))
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
        Accounts are created by the QSHET administrator. Contact the administrator if you need access.
    </p>
    </section>
    """
  return page(content)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
  if "user_id" not in session:
    return redirect(url_for("login"))
  if request.method == "POST":
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    is_valid, message = validate_password(new_password)
    if not is_valid:
      flash(message)
    elif new_password != confirm_password:
      flash("The new passwords do not match.")
    else:
      conn = get_db()
      try:
        with conn.cursor() as db:
          db.execute("SELECT password FROM users WHERE id = %s", (session["user_id"],))
          user = db.fetchone()
          if not user or not check_password_hash(user["password"], current_password):
            flash("Current password is incorrect.")
          else:
            db.execute("UPDATE users SET password = %s, must_change_password = 0 WHERE id = %s", (generate_password_hash(new_password), session["user_id"]))
            conn.commit()
            session["must_change_password"] = False
            log_action("change_password", "User changed password")
            flash("Password changed successfully.")
            return redirect(url_for("dashboard"))
      finally:
        conn.close()
  content = """
    <h2>Change Password</h2>
    <section class="panel" style="max-width:450px;margin:auto;">
      <p>Enter your current password, then choose a new password containing at least 8 characters, a letter, a number and a symbol.</p>
      <form method="post">
        <label>Current password</label><input type="password" name="current_password" required>
        <label>New password</label><input type="password" name="new_password" minlength="8" required>
        <label>Confirm new password</label><input type="password" name="confirm_password" minlength="8" required>
        <button type="submit">Change password</button>
      </form>
    </section>
  """
  return page(content)


@app.before_request
def require_password_change_first():
  if session.get("must_change_password") and request.endpoint not in {"change_password", "logout", "static"}:
    return redirect(url_for("change_password"))


@app.route("/logout")
def logout():
  session.clear()
  return redirect(url_for("login"))


# ---------- 1. DASHBOARD ----------


@app.route("/")
def dashboard():
  if "user_id" not in session:
    return redirect(url_for("login"))

  if session.get("role") != "admin":
    role = session.get("role", "staff")
    conn = get_db()
    try:
      with conn.cursor() as db:
        db.execute("SELECT COUNT(*) AS cnt FROM cidb_uploads WHERE user_id = %s", (session["user_id"],))
        my_docs = db.fetchone()["cnt"]

        my_tasks = 0
        overdue_tasks = 0
        my_logs = 0
        pending_docs = 0
        task_rows = []

        db.execute("SELECT COUNT(*) AS cnt FROM protege_tasks WHERE user_id=%s AND status NOT IN ('Completed','Cancelled')", (session["user_id"],))
        my_tasks = db.fetchone()["cnt"]
        db.execute("SELECT COUNT(*) AS cnt FROM protege_tasks WHERE user_id=%s AND status NOT IN ('Completed','Cancelled') AND due_date IS NOT NULL AND due_date < CURDATE()", (session["user_id"],))
        overdue_tasks = db.fetchone()["cnt"]
        db.execute("SELECT COUNT(*) AS cnt FROM protege_work_logs WHERE user_id=%s", (session["user_id"],))
        my_logs = db.fetchone()["cnt"]
        db.execute("SELECT COUNT(*) AS cnt FROM cidb_uploads WHERE user_id=%s AND review_status IN ('Pending','Needs Changes')", (session["user_id"],))
        pending_docs = db.fetchone()["cnt"]
        db.execute("SELECT id,title,priority,due_date,status FROM protege_tasks WHERE user_id=%s ORDER BY CASE WHEN status='Completed' THEN 1 ELSE 0 END, due_date IS NULL, due_date ASC, id DESC LIMIT 5", (session["user_id"],))
        task_rows = db.fetchall()

        db.execute("SELECT id,title,announcement_type,due_date,created_at FROM protege_announcements ORDER BY id DESC LIMIT 5")
        announcement_rows = db.fetchall()
    finally:
      conn.close()

    ann_html = "<ul>"
    if announcement_rows:
      for item in announcement_rows:
        due = item['due_date'].strftime('%d %b %Y') if item['due_date'] else 'No deadline'
        ann_html += f"<li><strong>{escape(item['title'])}</strong> — {escape(item['announcement_type'])} <span class='muted'>({due})</span></li>"
    else:
      ann_html += "<li class='muted'>No announcements yet.</li>"
    ann_html += "</ul>"

    task_html = "<div class='table-wrap'><table><thead><tr><th>Task</th><th>Priority</th><th>Due date</th><th>Status</th></tr></thead><tbody>"
    if task_rows:
      for task in task_rows:
        due = task['due_date'].strftime('%d %b %Y') if task['due_date'] else '—'
        task_html += f"<tr><td>{escape(task['title'])}</td><td>{escape(task['priority'])}</td><td>{due}</td><td><span class='badge'>{escape(task['status'])}</span></td></tr>"
    else:
      task_html += "<tr><td colspan='4' class='muted'>No tasks assigned yet.</td></tr>"
    task_html += "</tbody></table></div>"

    role_title = "Protégé" if role == "protege" else "Staff"
    content = f"""
      <h2>{role_title} Dashboard</h2>
      <p class="muted">Welcome, {escape(session.get('username', role_title) or role_title)}. Your personal QSHET workspace.</p>
      <div class="cards">
        <a href="/my-tasks" class="card">My Open Tasks<div class="number">{my_tasks}</div></a>
        <a href="/my-cidb" class="card">My Documents<div class="number">{my_docs}</div></a>
        <a href="/my-cidb" class="card">Documents Needing Review<div class="number">{pending_docs}</div></a>
        <a href="/my-tasks" class="card">Overdue Tasks<div class="number">{overdue_tasks}</div></a>
        <a href="/work-log" class="card">Work Logs Submitted<div class="number">{my_logs}</div></a>
      </div>
      <section class="panel"><h3>My Recent Tasks</h3>{task_html}<a class="btn" href="/my-tasks">View all tasks</a></section>
      <section class="panel"><h3>Latest Announcements</h3>{ann_html}<a class="btn" href="/announcements">View announcements</a></section>
      <section class="panel"><h3>Quick Actions</h3>
        <a class="btn" href="/my-profile">My Profile</a>
        <a class="btn" href="/work-log">Add Work Log</a>
        <a class="btn" href="/submit-safety">Submit Safety Report</a>
        <a class="btn" href="/my-cidb">Upload / Check Documents</a>
        <a class="btn" href="/my-training">View My Training</a>
        <a class="btn" href="/change-password">Change Password</a>
      </section>
    """
    return page(content)

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

      db.execute("SELECT expiry_date AS due_date FROM training WHERE expiry_date IS NOT NULL AND expiry_date <> '' UNION ALL SELECT review_date AS due_date FROM documents WHERE review_date IS NOT NULL AND review_date <> '' UNION ALL SELECT CAST(cidb_expiry AS CHAR) AS due_date FROM employees WHERE cidb_expiry IS NOT NULL")
      due_rows = db.fetchall()
      db.execute("SELECT COUNT(*) AS cnt FROM corrective_actions WHERE status NOT IN ('Resolved','Closed')")
      open_actions_count = db.fetchone()["cnt"]

      db.execute("""
                SELECT id, title, category, description, filename, status, created_at
                FROM safety_reports ORDER BY id DESC LIMIT 5
            """)
      recent = db.fetchall()
  finally:
    conn.close()

  today = date.today()
  expired_count = 0
  expiring_count = 0
  for due_row in due_rows:
    try:
      due = date.fromisoformat(str(due_row["due_date"])[:10])
      if due < today:
        expired_count += 1
      elif due <= today + timedelta(days=30):
        expiring_count += 1
    except (ValueError, TypeError):
      continue

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
        <a href="/reports" class="card">Expired dates
            <div class="number">{expired_count}</div></a>
        <a href="/reports" class="card">Due within 30 days
            <div class="number">{expiring_count}</div></a>
        <a href="/actions" class="card">Open corrective actions
            <div class="number">{open_actions_count}</div></a>
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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "safety")
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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "safety")

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
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Description</th><th>File</th><th>Status</th><th>Date</th><th>Action</th></tr></thead><tbody>"
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

    menu_id = f"safety_menu_{r['id']}"
    menu_items = f"""
        <button type="button" onclick="openEditSafetyModal('{r['id']}', '{escaped_title}', '{escaped_category}', '{escaped_desc}')">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
        </button>
        <form method="post" onsubmit="return confirm('Delete this report?');" style="margin:0;">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="report_id" value="{r['id']}">
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
    """
    actions_td = action_menu_html(menu_id, menu_items)

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
            <td>{actions_td}</td>
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
        <label>
            Attach Certificate / File (Optional)<br>
            <span style="font-size: 12px; font-weight: normal; color: #7a8c83;">
                Supported formats: PDF, JPG, PNG
            </span>
        </label>
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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "document")
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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "document")

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
    escaped_title = r["title"].replace("'", "\\'")
    r_date = r["review_date"] or ""

    menu_id = f"doc_menu_{r['id']}"
    menu_items = f"""
        <button type="button" onclick="openEditDocModal('{r['id']}', '{escaped_title}', '{r['doc_type']}', '{r_date}')">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
        </button>
        <form method="post" onsubmit="return confirm('Delete this document?');" style="margin:0;">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="doc_id" value="{r['id']}">
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
    """
    actions_td = action_menu_html(menu_id, menu_items)

    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td>{r['doc_type']}</td>
            <td>{file_link}</td>
            <td>{r['review_date'] or '-'}</td>
            <td>{actions_td}</td>
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
        <label>
            Attach Certificate / File (Optional)<br>
            <span style="font-size: 12px; font-weight: normal; color: #7a8c83;">
                Supported formats: PDF, JPG, PNG
            </span>
        </label>
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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "training")
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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "training")

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
      # Query training records and attempt to join user role via employees or users table
      db.execute(
          """
            SELECT t.id, t.employee, t.course, t.filename, t.expiry_date, u.role
            FROM training t
            LEFT JOIN users u ON (t.employee = u.username)
            ORDER BY t.id DESC
          """
      )
      rows = db.fetchall()
  finally:
    conn.close()

  # Categorize records into Protégé vs Staff
  protege_trainings = []
  staff_trainings = []

  for r in rows:
    emp_str = (r.get("employee") or "").lower()
    role_str = (r.get("role") or "").lower()

    if "protege" in emp_str or "protégé" in emp_str or role_str == "protege":
      protege_trainings.append(r)
    else:
      staff_trainings.append(r)

  def build_training_table(filtered_rows):
    t_html = (
        "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Employee"
        " Name / Staff ID</th><th>Training"
        " Course</th><th>File</th><th>Expiry"
        " Date</th><th>Action</th></tr></thead><tbody>"
    )
    if filtered_rows:
      for r in filtered_rows:
        file_link = (
            f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
            if r["filename"]
            else "-"
        )
        escaped_emp = r["employee"].replace("'", "\\'")
        escaped_crs = r["course"].replace("'", "\\'")
        e_date = r["expiry_date"] or ""

        menu_id = f"train_menu_{r['id']}"
        menu_items = f"""
            <button type="button" onclick="openEditTrainingModal('{r['id']}', '{escaped_emp}', '{escaped_crs}', '{e_date}')">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
            </button>
            <form method="post" onsubmit="return confirm('Delete this record?');" style="margin:0;">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="train_id" value="{r['id']}">
                <button type="submit" class="text-danger">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
                </button>
            </form>
        """
        actions_td = action_menu_html(menu_id, menu_items)

        t_html += f"""
            <tr>
                <td>{r['id']}</td>
                <td>{r['employee']}</td>
                <td>{r['course']}</td>
                <td>{file_link}</td>
                <td>{r['expiry_date'] or '-'}</td>
                <td>{actions_td}</td>
            </tr>
            """
    else:
      t_html += (
          "<tr><td colspan='6' class='muted'>No training records found.</td></tr>"
      )
    t_html += "</tbody></table></div>"
    return t_html

  content = f"""
    <h2>Training & Compliance</h2>
    <section class="panel">
    <h3>Add Training Record</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Employee Name or Staff ID</label>
        <input name="employee" required maxlength="100" placeholder="e.g., Nur Amira Najwa (PROTÉGÉ-001)">
        <label>Training Course</label>
        <input name="course" required maxlength="150">
        <label>Certificate Expiry Date</label>
        <input type="date" name="expiry_date">
        <label>
            Attach Certificate / File (Optional)<br>
            <span style="font-size: 12px; font-weight: normal; color: #7a8c83;">
                Supported formats: PDF, JPG, PNG
            </span>
        </label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf">
        <button type="submit">Save Training Record</button>
    </form>
    </section>
    <section class="panel">
        <h3>Protégé Training Records</h3>
        {build_training_table(protege_trainings)}
    </section>
    <section class="panel">
        <h3>Staff Training Records</h3>
        {build_training_table(staff_trainings)}
    </section>
    """
  return page(content)

# ---------- 5. USER / PROTÉGÉ CIDB RECORDS (User / Admin) ----------


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
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "cidb")
              if role == "admin":
                db.execute(
                    "UPDATE cidb_uploads SET title = %s, filename = %s WHERE id = %s",
                    (title, filename, record_id),
                )
              else:
                db.execute(
                    "UPDATE cidb_uploads SET title = %s, filename = %s, review_status='Pending', review_note=NULL, reviewed_at=NULL WHERE id = %s AND user_id = %s",
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
          if title and file and file.filename and valid_upload_file(file):
            filename = save_upload(file, "cidb")

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
                SELECT id, title, filename, uploaded_at, review_status, review_note, reviewed_at 
                FROM cidb_uploads WHERE user_id = %s ORDER BY id DESC
            """,
          (user_id,),
      )
      rows = db.fetchall()
  finally:
    conn.close()

  table_html = (
      "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Title</th><th>File</th><th>Uploaded"
      " Date</th><th>Review Status</th><th>Review Note</th><th>Action</th></tr></thead><tbody>"
  )
  for r in rows:
    file_link = f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
    escaped_title = r["title"].replace("'", "\\'")

    menu_id = f"mycidb_menu_{r['id']}"
    menu_items = f"""
        <button type="button" onclick="openEditCidbModal('{r['id']}', '{escaped_title}')">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
        </button>
        <form method="post" onsubmit="return confirm('Delete this record?');" style="margin:0;">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="record_id" value="{r['id']}">
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
    """
    actions_td = action_menu_html(menu_id, menu_items)

    table_html += f"""
        <tr>
            <td>{r['id']}</td>
            <td>{r['title']}</td>
            <td>{file_link}</td>
            <td>{r['uploaded_at']}</td>
            <td><span class="badge">{r.get('review_status', 'Pending')}</span></td>
            <td>{escape(r.get('review_note') or '—')}</td>
            <td>{actions_td}</td>
        </tr>
        """
  table_html += "</tbody></table></div>"

  content = f"""
    <h2>My CIDB Documents & Compliance Files</h2>
    <section class="panel">
    <h3>Upload New Document / CIDB Card</h3>
    <form method="post" enctype="multipart/form-data">
        <label>Document Title</label>
        <input name="title" required maxlength="150" placeholder="e.g., Green Card CIDB, CV, Certificate">
        <label>
            Attach Certificate / File (Optional)<br>
            <span style="font-size: 12px; font-weight: normal; color: #7a8c83;">
                Supported formats: PDF, JPG, PNG
            </span>
        </label>
        <input type="file" name="file" accept=".png, .jpg, .jpeg, .pdf" required>
        <button type="submit">Upload Document</button>
    </form>
    </section>
    <section class="panel"><h3>My Uploaded Records</h3>
    {table_html}
    </section>
    """
  return page(content)


# ---------- MY PROFILE ROUTE ----------

@app.route("/my-profile", methods=["GET", "POST"])
def my_profile():
  if "user_id" not in session:
    return redirect(url_for("login"))
  
  if session.get("role") == "admin":
    return redirect(url_for("employees"))

  user_id = session["user_id"]
  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT * FROM employees WHERE user_id = %s LIMIT 1", (user_id,))
      profile = db.fetchone()

      if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        if not full_name:
          flash("Full name is required.")
        else:
          staff_id = request.form.get("staff_id", "").strip() or None
          department = request.form.get("department", "").strip() or None
          position = request.form.get("position", "").strip() or None
          cidb_number = request.form.get("cidb_number", "").strip() or None
          cidb_expiry = request.form.get("cidb_expiry", "").strip() or None
          
          try:
            new_file = save_upload(request.files.get("attachment"), "my_profile")
          except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("my_profile"))

          if profile:
            filename = new_file or profile.get("filename")
            db.execute(
                """UPDATE employees 
                   SET full_name=%s, staff_id=%s, department=%s, position=%s, cidb_number=%s, cidb_expiry=%s, filename=%s 
                   WHERE user_id=%s""",
                (full_name, staff_id, department, position, cidb_number, cidb_expiry, filename, user_id)
            )
            conn.commit()
            if new_file and profile.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / profile["filename"]).unlink(missing_ok=True)
              except OSError: pass
          else:
            db.execute(
                """INSERT INTO employees (user_id, full_name, staff_id, department, position, cidb_number, cidb_expiry, employment_status, filename) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 'Active', %s)""",
                (user_id, full_name, staff_id, department, position, cidb_number, cidb_expiry, new_file)
            )
            conn.commit()

          log_action("update_my_profile", f"User {user_id} updated personal profile")
          flash("Your profile has been updated successfully.")
          return redirect(url_for("my_profile"))
  finally:
    conn.close()

  p = profile or {}
  field = lambda name: escape(str(p.get(name) or ""))
  file_link = f"<p>Current attachment: <a target='_blank' href='/uploads/{quote(str(p.get('filename')), safe='')}'>View file</a></p>" if p.get('filename') else ""

  content = f"""
    <h2>My Profile</h2>
    <p class="muted">View and update your personal personnel details, department placement, and CIDB information.</p>
    <section class="panel" style="max-width: 600px; margin: auto;">
      <form method="post" enctype="multipart/form-data">
        <label>Full Name</label>
        <input name="full_name" required maxlength="150" value="{field('full_name')}">
        
        <label>Staff ID</label>
        <input name="staff_id" maxlength="80" value="{field('staff_id')}" placeholder="e.g., EMP-001 or PRO-001">
        
        <label>Department</label>
        <input name="department" maxlength="100" value="{field('department')}" placeholder="e.g., QSHET Department">
        
        <label>Position / Role Title</label>
        <input name="position" maxlength="100" value="{field('position')}" placeholder="e.g., Protégé Trainee / Safety Officer">
        
        <label>CIDB Green Card Number</label>
        <input name="cidb_number" maxlength="100" value="{field('cidb_number')}">
        
        <label>CIDB Expiry Date</label>
        <input type="date" name="cidb_expiry" value="{field('cidb_expiry')}">
        
        <label>
            Attach / Update Certificate / ID Card (Optional)<br>
            <span style="font-size: 12px; font-weight: normal; color: #7a8c83;">Supported formats: PDF, JPG, PNG</span>
        </label>
        <input type="file" name="attachment" accept=".png, .jpg, .jpeg, .pdf">
        {file_link}
        
        <button type="submit" class="btn" style="margin-top: 15px;">Save Profile Changes</button>
      </form>
    </section>
  """
  return page(content)


# ---------- USER WORKSPACE: TASKS ----------

@app.route("/my-tasks", methods=["GET", "POST"])
def my_tasks():
  if "user_id" not in session:
    return redirect(url_for("login"))
  if session.get("role") == "admin":
    return redirect(url_for("tasks"))
  user_id = session["user_id"]
  if request.method == "POST":
    task_id = request.form.get("task_id", type=int)
    status = request.form.get("status", "In Progress").strip()
    note = request.form.get("completion_note", "").strip()
    if status not in ("To Do", "In Progress", "Completed"):
      flash("Invalid task status.")
      return redirect(url_for("my_tasks"))
    conn = get_db()
    try:
      with conn.cursor() as db:
        db.execute("UPDATE protege_tasks SET status=%s, completion_note=%s, completed_at=%s WHERE id=%s AND user_id=%s",
                   (status, note or None, datetime.now() if status == "Completed" else None, task_id, user_id))
      conn.commit()
    finally:
      conn.close()
    log_action("update_task_progress", f"Task {task_id}: {status}")
    flash("Task progress updated.")
    return redirect(url_for("my_tasks"))
  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT * FROM protege_tasks WHERE user_id=%s ORDER BY CASE WHEN status='Completed' THEN 1 ELSE 0 END, due_date IS NULL, due_date ASC, id DESC", (user_id,))
      rows = db.fetchall()
  finally:
    conn.close()
  html = "<div class='table-wrap'><table><thead><tr><th>Task</th><th>Priority</th><th>Due</th><th>Status / Update</th></tr></thead><tbody>"
  if rows:
    for r in rows:
      due = r['due_date'].strftime('%d %b %Y') if r['due_date'] else '—'
      html += f"<tr><td><strong>{escape(r['title'])}</strong><br>{escape(r['description'] or '')}</td><td>{escape(r['priority'])}</td><td>{due}</td><td><form method='post'><input type='hidden' name='task_id' value='{r['id']}'><select name='status'><option {'selected' if r['status']=='To Do' else ''}>To Do</option><option {'selected' if r['status']=='In Progress' else ''}>In Progress</option><option {'selected' if r['status']=='Completed' else ''}>Completed</option></select><textarea name='completion_note' rows='2' placeholder='Progress / completion note'>{escape(r['completion_note'] or '')}</textarea><button class='btn-sm' type='submit'>Save Progress</button></form></td></tr>"
  else:
    html += "<tr><td colspan='4' class='muted'>No tasks have been assigned to you yet.</td></tr>"
  html += "</tbody></table></div>"
  return page(f"<h2>My Tasks & Assignments</h2><p class='muted'>Update progress on your assigned tasks. Only your own assignments are shown here.</p><section class='panel'>{html}</section>")


@app.route("/tasks", methods=["GET", "POST"])
def tasks():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))
  conn = get_db()
  try:
    if request.method == "POST":
      action = request.form.get("action", "create")
      if action == "delete":
        task_id = request.form.get("task_id", type=int)
        with conn.cursor() as db:
          db.execute("DELETE FROM protege_tasks WHERE id=%s", (task_id,))
        conn.commit()
        log_action("delete_user_task", f"Task {task_id}")
        flash("Task deleted.")
        return redirect(url_for("tasks"))
      elif action == "edit":
        task_id = request.form.get("task_id", type=int)
        user_id = request.form.get("user_id", type=int)
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        priority = request.form.get("priority", "Normal")
        due_raw = request.form.get("due_date", "").strip() or None
        if not task_id or not user_id or not title:
          flash("Task ID, assigned user, and title are required for updating.")
        else:
          with conn.cursor() as db:
            db.execute("UPDATE protege_tasks SET user_id=%s, title=%s, description=%s, priority=%s, due_date=%s WHERE id=%s",
                       (user_id, title, description or None, priority, due_raw, task_id))
          conn.commit()
          log_action("edit_user_task", f"Updated task {task_id}")
          flash("Task updated successfully.")
          return redirect(url_for("tasks"))
      
      user_id = request.form.get("user_id", type=int)
      title = request.form.get("title", "").strip()
      description = request.form.get("description", "").strip()
      priority = request.form.get("priority", "Normal")
      due_raw = request.form.get("due_date", "").strip()
      if not user_id or not title:
        flash("Select a user and enter a task title.")
      else:
        with conn.cursor() as db:
          db.execute("SELECT id FROM users WHERE id=%s AND role IN ('protege', 'staff')", (user_id,))
          target = db.fetchone()
          if not target:
            flash("Selected account is not a valid Protégé or Staff member.")
          else:
            db.execute("INSERT INTO protege_tasks (user_id,title,description,priority,due_date,created_by) VALUES (%s,%s,%s,%s,%s,%s)",
                       (user_id,title,description or None,priority,due_raw or None,session.get('user_id')))
            conn.commit()
            log_action("create_user_task", f"Assigned task '{title}' to user {user_id}")
            flash("Task assigned successfully.")
            return redirect(url_for("tasks"))
    with conn.cursor() as db:
      db.execute("SELECT id,username,role FROM users WHERE role IN ('protege','staff') ORDER BY role, username")
      users = db.fetchall()
      db.execute("SELECT t.*,u.username,u.role FROM protege_tasks t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC")
      rows = db.fetchall()
  finally:
    conn.close()
  user_options = "".join(f"<option value='{u['id']}'>{escape(u['username'])} ({escape(u['role'].capitalize())})</option>" for u in users)

  def build_task_table(filtered_rows):
    t_html = "<div class='table-wrap'><table><thead><tr><th>Assignee</th><th>Task</th><th>Priority</th><th>Due</th><th>Status</th><th>Action</th></tr></thead><tbody>"
    if filtered_rows:
      for r in filtered_rows:
        due = r['due_date'].strftime('%d %b %Y') if r['due_date'] else '—'
        due_iso = r['due_date'].strftime('%Y-%m-%d') if r['due_date'] else ''
        escaped_title = (r['title'] or '').replace("'", "\\'")
        escaped_desc = (r['description'] or '').replace("'", "\\'").replace("\n", " ")
        menu_id = f"task_menu_{r['id']}"
        menu_items = f"""
            <button type="button" onclick="openEditTaskModal('{r['id']}', '{r['user_id']}', '{escaped_title}', '{escaped_desc}', '{r['priority']}', '{due_iso}')">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
            </button>
            <form method='post' onsubmit="return confirm('Delete this task?')" style="margin:0;">
                <input type='hidden' name='action' value='delete'>
                <input type='hidden' name='task_id' value='{r['id']}'>
                <button type="submit" class="text-danger">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
                </button>
            </form>
        """
        actions_td = action_menu_html(menu_id, menu_items)
        t_html += f"<tr><td>{escape(r['username'])}</td><td>{escape(r['title'])}<br><span class='muted'>{escape(r['description'] or '')}</span></td><td>{escape(r['priority'])}</td><td>{due}</td><td>{escape(r['status'])}</td><td>{actions_td}</td></tr>"
    else:
      t_html += "<tr><td colspan='6' class='muted'>No tasks assigned.</td></tr>"
    t_html += "</tbody></table></div>"
    return t_html

  protege_tasks = [r for r in rows if r.get('role') == 'protege']
  staff_tasks = [r for r in rows if r.get('role') == 'staff']

  return page(f"""
    <h2>Task Management (Protégés & Staff)</h2>
    <section class='panel'>
      <h3>Assign a Task</h3>
      <form method='post'>
        <label>Assignee (Protégé or Staff)</label>
        <select name='user_id' required>{user_options}</select>
        <label>Task title</label>
        <input name='title' maxlength='180' required>
        <label>Description / expected output</label>
        <textarea name='description' rows='3'></textarea>
        <label>Priority</label>
        <select name='priority'>
          <option>Low</option>
          <option selected>Normal</option>
          <option>High</option>
          <option>Urgent</option>
        </select>
        <label>Due date</label>
        <input type='date' name='due_date'>
        <button type='submit'>Assign Task</button>
      </form>
    </section>
    <section class='panel'>
      <h3>Protégé Tasks</h3>
      {build_task_table(protege_tasks)}
    </section>
    <section class='panel'>
      <h3>Staff Tasks</h3>
      {build_task_table(staff_tasks)}
    </section>
  """)


# ---------- WORK DIARY ----------

@app.route("/work-log", methods=["GET", "POST"])
def work_log():
  if "user_id" not in session:
    return redirect(url_for("login"))
  is_admin = session.get("role") == "admin"
  conn = get_db()
  try:
    if request.method == "POST":
      action = request.form.get("action", "add")
      if action == "delete":
        log_id = request.form.get("log_id", type=int)
        with conn.cursor() as db:
          if is_admin:
            db.execute("DELETE FROM protege_work_logs WHERE id=%s", (log_id,))
          else:
            db.execute("DELETE FROM protege_work_logs WHERE id=%s AND user_id=%s", (log_id, session["user_id"]))
        conn.commit()
        flash("Work log deleted.")
        return redirect(url_for("work_log"))
      elif action == "edit":
        log_id = request.form.get("log_id", type=int)
        activity_date = request.form.get("activity_date", "").strip()
        title = request.form.get("activity_title", "").strip()
        description = request.form.get("description", "").strip()
        skills = request.form.get("skills_learned", "").strip()
        challenges = request.form.get("challenges", "").strip()
        hours = request.form.get("hours_spent", "").strip() or None
        try:
          if hours is not None and (float(hours) < 0 or float(hours) > 24):
            raise ValueError
        except ValueError:
          flash("Hours must be a number between 0 and 24.")
          return redirect(url_for("work_log"))
        if not log_id or not activity_date or not title:
          flash("Activity date and title are required.")
          return redirect(url_for("work_log"))
        with conn.cursor() as db:
          if is_admin:
            db.execute("UPDATE protege_work_logs SET activity_date=%s, activity_title=%s, description=%s, skills_learned=%s, challenges=%s, hours_spent=%s WHERE id=%s",
                       (activity_date, title, description or None, skills or None, challenges or None, hours, log_id))
          else:
            db.execute("UPDATE protege_work_logs SET activity_date=%s, activity_title=%s, description=%s, skills_learned=%s, challenges=%s, hours_spent=%s WHERE id=%s AND user_id=%s",
                       (activity_date, title, description or None, skills or None, challenges or None, hours, log_id, session["user_id"]))
        conn.commit()
        flash("Work log updated.")
        return redirect(url_for("work_log"))

      if is_admin:
        flash("Admins can review logs here; users submit their own logs from their account.")
        return redirect(url_for("work_log"))
      activity_date = request.form.get("activity_date", "").strip()
      title = request.form.get("activity_title", "").strip()
      description = request.form.get("description", "").strip()
      skills = request.form.get("skills_learned", "").strip()
      challenges = request.form.get("challenges", "").strip()
      hours = request.form.get("hours_spent", "").strip() or None
      try:
        if hours is not None and (float(hours) < 0 or float(hours) > 24):
          raise ValueError
      except ValueError:
        flash("Hours must be a number between 0 and 24.")
        return redirect(url_for("work_log"))
      if not activity_date or not title:
        flash("Activity date and title are required.")
        return redirect(url_for("work_log"))
      with conn.cursor() as db:
        db.execute("INSERT INTO protege_work_logs (user_id,activity_date,activity_title,description,skills_learned,challenges,hours_spent) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                   (session['user_id'],activity_date,title,description or None,skills or None,challenges or None,hours))
      conn.commit()
      log_action("submit_work_log", title)
      flash("Work log submitted.")
      return redirect(url_for("work_log"))
    with conn.cursor() as db:
      if is_admin:
        db.execute("SELECT l.*,u.username,u.role FROM protege_work_logs l JOIN users u ON u.id=l.user_id ORDER BY l.activity_date DESC,l.id DESC")
      else:
        db.execute("SELECT l.*,u.username,u.role FROM protege_work_logs l JOIN users u ON u.id=l.user_id WHERE l.user_id=%s ORDER BY l.activity_date DESC,l.id DESC", (session['user_id'],))
      rows = db.fetchall()
  finally:
    conn.close()

  def build_worklog_table(filtered_rows):
    t_html = "<div class='table-wrap'><table><thead><tr><th>Date</th><th>User</th><th>Activity</th><th>Skills learned</th><th>Hours</th><th>Review</th><th>Action</th></tr></thead><tbody>"
    if filtered_rows:
      for r in filtered_rows:
        d = r['activity_date'].strftime('%d %b %Y') if r['activity_date'] else '—'
        d_iso = r['activity_date'].strftime('%Y-%m-%d') if r['activity_date'] else ''
        escaped_title = (r['activity_title'] or '').replace("'", "\\'")
        escaped_desc = (r['description'] or '').replace("'", "\\'").replace("\n", " ")
        escaped_skills = (r['skills_learned'] or '').replace("'", "\\'").replace("\n", " ")
        escaped_chal = (r['challenges'] or '').replace("'", "\\'").replace("\n", " ")
        hours_val = r['hours_spent'] if r['hours_spent'] is not None else ''

        menu_id = f"worklog_menu_{r['id']}"
        menu_items = f"""
            <button type="button" onclick="openEditWorkLogModal('{r['id']}', '{d_iso}', '{escaped_title}', '{escaped_desc}', '{escaped_skills}', '{escaped_chal}', '{hours_val}')">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
            </button>
            <form method='post' onsubmit="return confirm('Delete this work log?')" style="margin:0;">
                <input type='hidden' name='action' value='delete'>
                <input type='hidden' name='log_id' value='{r['id']}'>
                <button type="submit" class="text-danger">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
                </button>
            </form>
        """
        actions_td = action_menu_html(menu_id, menu_items)
        t_html += f"<tr><td>{d}</td><td>{escape(r['username'])}</td><td><strong>{escape(r['activity_title'])}</strong><br>{escape(r['description'] or '')}<br><span class='muted'>Challenges: {escape(r['challenges'] or '—')}</span></td><td>{escape(r['skills_learned'] or '—')}</td><td>{escape(str(r['hours_spent']) if r['hours_spent'] is not None else '—')}</td><td>{escape(r['status'])}{('<br>'+escape(r['supervisor_feedback'])) if r['supervisor_feedback'] else ''}</td><td>{actions_td}</td></tr>"
    else:
      t_html += "<tr><td colspan='7' class='muted'>No work logs submitted.</td></tr>"
    t_html += "</tbody></table></div>"
    return t_html

  if is_admin:
    protege_logs = [r for r in rows if r.get('role') == 'protege']
    staff_logs = [r for r in rows if r.get('role') == 'staff']
    content = f"""
      <h2>Work Logs (Protégés & Staff)</h2>
      <section class='panel'>
        <h3>Protégé Work Logs</h3>
        {build_worklog_table(protege_logs)}
      </section>
      <section class='panel'>
        <h3>Staff Work Logs</h3>
        {build_worklog_table(staff_logs)}
      </section>
    """
    return page(content)
  else:
    form = f"<section class='panel'><h3>Submit Work Log</h3><form method='post'><label>Activity date</label><input type='date' name='activity_date' value='{date.today().isoformat()}' required><label>Activity / task title</label><input name='activity_title' maxlength='180' required><label>What did you do?</label><textarea name='description' rows='3'></textarea><label>Skills or knowledge learned</label><textarea name='skills_learned' rows='2'></textarea><label>Challenges / follow-up needed</label><textarea name='challenges' rows='2'></textarea><label>Hours spent (optional)</label><input type='number' name='hours_spent' min='0' max='24' step='0.25'><button type='submit'>Submit Work Log</button></form></section>"
    table = build_worklog_table(rows)
    return page(f"<h2>My Daily / Weekly Work Log</h2><p class='muted'>Record your activities, what you learned, and any follow-up needed.</p>{form}<section class='panel'><h3>My Submitted Logs</h3>{table}</section>")


# ---------- TRAINING VIEW ----------

@app.route("/my-training")
def my_training():
  if "user_id" not in session:
    return redirect(url_for("login"))
  if session.get("role") == "admin":
    return redirect(url_for("training"))
  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT full_name FROM employees WHERE user_id=%s LIMIT 1", (session['user_id'],))
      employee = db.fetchone()
      names = [session.get('username','')]
      if employee and employee.get('full_name'):
        names.append(employee['full_name'])
      placeholders = ','.join(['%s'] * len(names))
      db.execute(f"SELECT employee,course,filename,expiry_date FROM training WHERE employee IN ({placeholders}) ORDER BY course", tuple(names))
      rows = db.fetchall()
  finally:
    conn.close()
  today = date.today()
  html = "<div class='table-wrap'><table><thead><tr><th>Course / Training</th><th>Expiry date</th><th>Status</th><th>Certificate</th></tr></thead><tbody>"
  for r in rows:
    status = 'No expiry recorded'
    try:
      expiry = date.fromisoformat(str(r['expiry_date'])[:10]) if r['expiry_date'] else None
      if expiry:
        status = 'Expired' if expiry < today else ('Expiring soon' if expiry <= today + timedelta(days=30) else 'Valid')
    except ValueError:
      pass
    link = f"<a href='/uploads/{quote(r['filename'])}' target='_blank'>View file</a>" if r['filename'] else '—'
    html += f"<tr><td>{escape(r['course'])}</td><td>{escape(str(r['expiry_date'] or '—'))}</td><td><span class='badge'>{status}</span></td><td>{link}</td></tr>"
  if not rows:
    html += "<tr><td colspan='4' class='muted'>No training records matched your account yet. Ask the QSHET administrator to link your training record to your username or employee profile name.</td></tr>"
  html += "</tbody></table></div>"
  return page(f"<h2>My Training & Compliance</h2><p class='muted'>This page shows training records linked to your username or employee profile.</p><section class='panel'>{html}</section>")


# ---------- SAFETY SUBMISSIONS ----------

@app.route("/submit-safety", methods=["GET", "POST"])
def submit_safety():
  if "user_id" not in session:
    return redirect(url_for("login"))
  is_admin = session.get("role") == "admin"
  conn = get_db()
  try:
    if request.method == "POST":
      action = request.form.get("action", "add")
      if action == "delete":
        sub_id = request.form.get("submission_id", type=int)
        with conn.cursor() as db:
          if is_admin:
            db.execute("SELECT filename FROM protege_safety_submissions WHERE id=%s", (sub_id,))
            row = db.fetchone()
            if row and row["filename"]:
              f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
              if f_path.exists(): f_path.unlink(missing_ok=True)
            db.execute("DELETE FROM protege_safety_submissions WHERE id=%s", (sub_id,))
          else:
            db.execute("SELECT filename FROM protege_safety_submissions WHERE id=%s AND user_id=%s", (sub_id, session["user_id"]))
            row = db.fetchone()
            if row and row["filename"]:
              f_path = app.config["UPLOAD_FOLDER"] / row["filename"]
              if f_path.exists(): f_path.unlink(missing_ok=True)
            db.execute("DELETE FROM protege_safety_submissions WHERE id=%s AND user_id=%s", (sub_id, session["user_id"]))
        conn.commit()
        flash("Safety submission deleted.")
        return redirect(url_for("submit_safety"))
      elif action == "edit":
        sub_id = request.form.get("submission_id", type=int)
        title = request.form.get('title','').strip()
        category = request.form.get('category','Other').strip()
        location = request.form.get('location','').strip()
        description = request.form.get('description','').strip()
        file = request.files.get('file')
        if not sub_id or not title or not description:
          flash('Submission ID, title, and description are required.')
        else:
          new_file = save_upload(file, 'safety') if file and file.filename else None
          with conn.cursor() as db:
            if is_admin:
              db.execute("SELECT filename FROM protege_safety_submissions WHERE id=%s", (sub_id,))
              row = db.fetchone()
              filename = new_file or (row.get("filename") if row else None)
              db.execute("UPDATE protege_safety_submissions SET title=%s, category=%s, location=%s, description=%s, filename=%s WHERE id=%s",
                         (title, category, location or None, description, filename, sub_id))
            else:
              db.execute("SELECT filename FROM protege_safety_submissions WHERE id=%s AND user_id=%s", (sub_id, session["user_id"]))
              row = db.fetchone()
              filename = new_file or (row.get("filename") if row else None)
              db.execute("UPDATE protege_safety_submissions SET title=%s, category=%s, location=%s, description=%s, filename=%s, status='Submitted', admin_response=NULL WHERE id=%s AND user_id=%s",
                         (title, category, location or None, description, filename, sub_id, session["user_id"]))
          conn.commit()
          flash("Safety submission updated.")
          return redirect(url_for("submit_safety"))

      if is_admin:
        submission_id = request.form.get('submission_id', type=int)
        status = request.form.get('status', 'Submitted')
        response = request.form.get('admin_response', '').strip()
        if status not in ('Submitted','Under Review','Action Required','Resolved','Closed'):
          flash('Invalid status.')
        else:
          with conn.cursor() as db:
            db.execute("UPDATE protege_safety_submissions SET status=%s,admin_response=%s WHERE id=%s", (status,response or None,submission_id))
          conn.commit()
          log_action('review_user_safety_submission', f'Submission {submission_id}: {status}')
          flash('Safety submission updated.')
        return redirect(url_for('submit_safety'))
      title = request.form.get('title','').strip()
      category = request.form.get('category','Other').strip()
      location = request.form.get('location','').strip()
      description = request.form.get('description','').strip()
      file = request.files.get('file')
      if not title or not description:
        flash('Title and description are required.')
        return redirect(url_for('submit_safety'))
      filename = save_upload(file, 'safety') if file and file.filename else None
      with conn.cursor() as db:
        db.execute("INSERT INTO protege_safety_submissions (user_id,title,category,location,description,filename) VALUES (%s,%s,%s,%s,%s,%s)",
                   (session['user_id'],title,category,location or None,description,filename))
      conn.commit()
      log_action('submit_user_safety_report', title)
      flash('Safety concern submitted to QSHET.')
      return redirect(url_for('submit_safety'))
    with conn.cursor() as db:
      if is_admin:
        db.execute("SELECT s.*,u.username,u.role FROM protege_safety_submissions s JOIN users u ON u.id=s.user_id ORDER BY s.id DESC")
      else:
        db.execute("SELECT s.*,u.username,u.role FROM protege_safety_submissions s JOIN users u ON u.id=s.user_id WHERE s.user_id=%s ORDER BY s.id DESC", (session['user_id'],))
      rows = db.fetchall()
  finally:
    conn.close()

  def build_safety_table(filtered_rows):
    t_html = "<div class='table-wrap'><table><thead><tr><th>Date</th><th>Submitted by</th><th>Concern</th><th>Location</th><th>Status / response</th>"
    if is_admin: t_html += "<th>Review</th>"
    t_html += "<th>Action</th></tr></thead><tbody>"
    if filtered_rows:
      for r in filtered_rows:
        created = r['created_at'].strftime('%d %b %Y %H:%M') if r['created_at'] else '—'
        file_link = f"<br><a href='/uploads/{quote(r['filename'])}' target='_blank'>Attachment</a>" if r['filename'] else ''
        status_options = "".join("<option %s>%s</option>" % ("selected" if r['status'] == st else "", st) for st in ['Submitted', 'Under Review', 'Action Required', 'Resolved', 'Closed'])
        review = f"<form method='post'><input type='hidden' name='submission_id' value='{r['id']}'><select name='status'>{status_options}</select><textarea name='admin_response' rows='2' placeholder='Response / action taken'>{escape(r['admin_response'] or '')}</textarea><button class='btn-sm'>Save</button></form>" if is_admin else ""
        escaped_title = (r['title'] or '').replace("'", "\\'")
        escaped_loc = (r['location'] or '').replace("'", "\\'")
        escaped_desc = (r['description'] or '').replace("'", "\\'").replace("\n", " ")
        menu_id = f"safetysub_menu_{r['id']}"
        menu_items = f"""
            <button type="button" onclick="openEditSafetySubModal('{r['id']}', '{escaped_title}', '{r['category']}', '{escaped_loc}', '{escaped_desc}')">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
            </button>
            <form method='post' onsubmit="return confirm('Delete this safety submission?')" style="margin:0;">
                <input type='hidden' name='action' value='delete'>
                <input type='hidden' name='submission_id' value='{r['id']}'>
                <button type="submit" class="text-danger">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
                </button>
            </form>
        """
        actions_td = action_menu_html(menu_id, menu_items)
        t_html += f"<tr><td>{created}</td><td>{escape(r['username'])}</td><td><strong>{escape(r['title'])}</strong> ({escape(r['category'])})<br>{escape(r['description'])}{file_link}</td><td>{escape(r['location'] or '—')}</td><td><span class='badge'>{escape(r['status'])}</span><br>{escape(r['admin_response'] or 'No response yet')}</td>" + (f"<td>{review}</td>" if is_admin else '') + f"<td>{actions_td}</td></tr>"
    else:
      t_html += f"<tr><td colspan='{(7 if is_admin else 6)}' class='muted'>No submissions.</td></tr>"
    t_html += "</tbody></table></div>"
    return t_html

  if is_admin:
    protege_subs = [r for r in rows if r.get('role') == 'protege']
    staff_subs = [r for r in rows if r.get('role') == 'staff']
    content = f"""
      <h2>Safety Inbox (Protégés & Staff)</h2>
      <section class='panel'>
        <h3>Protégé Submissions</h3>
        {build_safety_table(protege_subs)}
      </section>
      <section class='panel'>
        <h3>Staff Submissions</h3>
        {build_safety_table(staff_subs)}
      </section>
    """
    return page(content)
  else:
    form = "<section class='panel'><h3>Submit a Safety Concern / Hazard</h3><p class='muted'>For emergencies, immediately notify the site supervisor or emergency response team. This form is for recording and follow-up, not emergency response.</p><form method='post' enctype='multipart/form-data'><label>Title</label><input name='title' maxlength='150' required><label>Category</label><select name='category'><option>Hazard</option><option>Near Miss</option><option>Unsafe Act</option><option>Unsafe Condition</option><option>Environmental</option><option>Traffic</option><option>Other</option></select><label>Location / site</label><input name='location' maxlength='180'><label>Description</label><textarea name='description' rows='4' required></textarea><label>Attach photo / document (optional)</label><input type='file' name='file' accept='.pdf,.png,.jpg,.jpeg'><button type='submit'>Submit to QSHET</button></form></section>"
    table = build_safety_table(rows)
    return page(f"<h2>Submit Safety Report</h2>{form}<section class='panel'><h3>My Submissions & Status</h3>{table}</section>")


# ---------- ANNOUNCEMENTS ----------

@app.route("/announcements", methods=["GET", "POST"])
def announcements():
  if "user_id" not in session:
    return redirect(url_for("login"))
  is_admin = session.get('role') == 'admin'
  conn = get_db()
  try:
    if request.method == 'POST' and is_admin:
      action = request.form.get('action','create')
      if action == 'delete':
        with conn.cursor() as db:
          db.execute("DELETE FROM protege_announcements WHERE id=%s", (request.form.get('announcement_id',type=int),))
        conn.commit()
        flash('Announcement deleted.')
        return redirect(url_for('announcements'))
      elif action == 'edit':
        ann_id = request.form.get('announcement_id', type=int)
        title = request.form.get('title','').strip()
        body = request.form.get('body','').strip()
        typ = request.form.get('announcement_type','General').strip()
        due = request.form.get('due_date','').strip() or None
        if not ann_id or not title or not body:
          flash('Announcement ID, title, and details are required.')
        else:
          with conn.cursor() as db:
            db.execute("UPDATE protege_announcements SET title=%s, body=%s, announcement_type=%s, due_date=%s WHERE id=%s",
                       (title, body, typ, due, ann_id))
          conn.commit()
          log_action('edit_announcement', f'Updated announcement {ann_id}')
          flash('Announcement updated successfully.')
          return redirect(url_for('announcements'))

      title = request.form.get('title','').strip()
      body = request.form.get('body','').strip()
      typ = request.form.get('announcement_type','General').strip()
      due = request.form.get('due_date','').strip() or None
      if not title or not body:
        flash('Announcement title and details are required.')
      else:
        with conn.cursor() as db:
          db.execute("INSERT INTO protege_announcements (title,body,announcement_type,due_date,created_by) VALUES (%s,%s,%s,%s,%s)", (title,body,typ,due,session['user_id']))
        conn.commit()
        log_action('create_announcement',title)
        flash('Announcement published.')
        return redirect(url_for('announcements'))
    with conn.cursor() as db:
      db.execute("SELECT a.*,u.username AS author FROM protege_announcements a LEFT JOIN users u ON u.id=a.created_by ORDER BY a.id DESC")
      rows = db.fetchall()
  finally:
    conn.close()
  form = ""
  if is_admin:
    form = "<section class='panel'><h3>Publish Announcement / Reminder</h3><form method='post'><label>Title</label><input name='title' maxlength='180' required><label>Details</label><textarea name='body' rows='4' required></textarea><label>Type</label><select name='announcement_type'><option>General</option><option>Training</option><option>Safety Briefing</option><option>Deadline</option><option>Meeting</option><option>Site Notice</option></select><label>Deadline (optional)</label><input type='date' name='due_date'><button type='submit'>Publish</button></form></section>"
  cards = ''
  for r in rows:
    due = r['due_date'].strftime('%d %b %Y') if r['due_date'] else 'No deadline'
    due_iso = r['due_date'].strftime('%Y-%m-%d') if r['due_date'] else ''
    created = r['created_at'].strftime('%d %b %Y') if r['created_at'] else ''
    escaped_title = (r['title'] or '').replace("'", "\\'")
    escaped_body = (r['body'] or '').replace("'", "\\'").replace("\n", " ")

    menu_id = f"ann_menu_{r['id']}"
    menu_items = f""
    if is_admin:
      menu_items += f"""
        <button type="button" onclick="openEditAnnouncementModal('{r['id']}', '{escaped_title}', '{escaped_body}', '{r['announcement_type']}', '{due_iso}')">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
        </button>
        <form method='post' onsubmit="return confirm('Delete announcement?')" style="margin:0;">
            <input type='hidden' name='action' value='delete'>
            <input type='hidden' name='announcement_id' value='{r['id']}'>
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
      """
    action_menu_block = f"<div style='margin-top:10px;'>{action_menu_html(menu_id, menu_items)}</div>" if is_admin else ''
    cards += f"<article class='panel'><span class='badge'>{escape(r['announcement_type'])}</span><h3>{escape(r['title'])}</h3><p>{escape(r['body'])}</p><p class='muted'>Posted {created} by {escape(r['author'] or 'QSHET Admin')} · {due}</p>{action_menu_block}</article>"
  if not cards: cards = "<section class='panel muted'>No announcements have been published.</section>"
  return page(f"<h2>Announcements & Reminders</h2>{form}{cards}")


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
        elif action == "review" and record_id:
          review_status = request.form.get("review_status", "Pending").strip()
          review_note = request.form.get("review_note", "").strip()
          if review_status not in ("Pending", "Approved", "Needs Changes"):
            flash("Invalid document review status.")
          else:
            db.execute("UPDATE cidb_uploads SET review_status=%s, review_note=%s, reviewed_at=NOW() WHERE id=%s", (review_status, review_note or None, record_id))
            log_action("review_document", f"Document {record_id}: {review_status}")
        elif action == "edit" and record_id:
          title = request.form.get("title", "").strip()
          file = request.files.get("file")
          if title:
            if file and file.filename and valid_upload_file(file):
              filename = save_upload(file, "cidb_admin")
              db.execute(
                  "UPDATE cidb_uploads SET title = %s, filename = %s, review_status='Pending', review_note=NULL, reviewed_at=NULL WHERE id = %s",
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
                SELECT c.id, u.username, u.role, c.title, c.filename, c.uploaded_at, c.review_status, c.review_note 
                FROM cidb_uploads c JOIN users u ON c.user_id = u.id 
                ORDER BY c.id DESC
            """)
      rows = db.fetchall()
  finally:
    conn.close()

  def build_cidb_table(filtered_rows):
    t_html = "<div class='table-wrap'><table><thead><tr><th>ID</th><th>Username</th><th>Title</th><th>File</th><th>Uploaded Date</th><th>Review</th><th>Action</th></tr></thead><tbody>"
    if filtered_rows:
      for r in filtered_rows:
        file_link = f'<a href="/uploads/{r["filename"]}" target="_blank">View File</a>'
        escaped_title = r["title"].replace("'", "\\'")
        menu_id = f"managecidb_menu_{r['id']}"
        menu_items = f"""
            <button type="button" onclick="openEditCidbModal('{r['id']}', '{escaped_title}')">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
            </button>
            <form method="post" onsubmit="return confirm('Delete this record?');" style="margin:0;">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="record_id" value="{r['id']}">
                <button type="submit" class="text-danger">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
                </button>
            </form>
        """
        actions_td = action_menu_html(menu_id, menu_items)
        t_html += f"""
            <tr>
                <td>{r['id']}</td>
                <td><strong>{r['username']}</strong></td>
                <td>{r['title']}</td>
                <td>{file_link}</td>
                <td>{r['uploaded_at']}</td>
                <td>
                    <form method="post">
                        <input type="hidden" name="action" value="review">
                        <input type="hidden" name="record_id" value="{r['id']}">
                        <select name="review_status">
                            <option {'selected' if r.get('review_status') == 'Pending' else ''}>Pending</option>
                            <option {'selected' if r.get('review_status') == 'Approved' else ''}>Approved</option>
                            <option {'selected' if r.get('review_status') == 'Needs Changes' else ''}>Needs Changes</option>
                        </select>
                        <textarea name="review_note" rows="2" placeholder="Review note">{escape(r.get('review_note') or '')}</textarea>
                        <button class="btn-sm" type="submit">Save Review</button>
                    </form>
                </td>
                <td>{actions_td}</td>
            </tr>
            """
    else:
      t_html += "<tr><td colspan='7' class='muted'>No records found.</td></tr>"
    t_html += "</tbody></table></div>"
    return t_html

  protege_docs = [r for r in rows if r.get('role') == 'protege']
  staff_docs = [r for r in rows if r.get('role') == 'staff']

  content = f"""
    <h2>All User CIDB & Compliance Records</h2>
    <section class="panel">
      <h3>Protégé Documents</h3>
      {build_cidb_table(protege_docs)}
    </section>
    <section class="panel">
      <h3>Staff Documents</h3>
      {build_cidb_table(staff_docs)}
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
          full_name = request.form.get("new_full_name", "").strip()
          new_role = request.form.get("new_role", "protege").strip().lower()

          if new_role not in ("admin", "protege", "staff"):
            flash("Invalid role selected.")
          elif not new_username or not new_password:
            flash("Username and temporary password are required.")
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
                    "INSERT INTO users (username, password, role, must_change_password) VALUES (%s, %s, %s, 1)",
                    (new_username, hashed_pw, new_role),
                )
                new_user_id = db.lastrowid
                if full_name:
                  position = "Administrator" if new_role == "admin" else ("Protégé" if new_role == "protege" else "Staff")
                  db.execute("INSERT INTO employees (user_id, full_name, position) VALUES (%s, %s, %s)", (new_user_id, full_name, position))
                conn.commit()
                log_action("create_user_account", f"Created {new_role} account: {new_username}")
                role_label = "administrator" if new_role == "admin" else ("Protégé" if new_role == "protege" else "Staff")
                flash(f"{role_label.capitalize()} account created. Share the temporary password securely; the user must change it on first login.")

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
    menu_id = f"user_menu_{u['id']}"
    menu_items = f"""
        <a href="/edit-user/{u['id']}">
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Update
        </a>
    """
    if not is_current:
      menu_items += f"""
        <form method="post" onsubmit="return confirm('Delete this user and their records?');" style="margin:0;">
            <input type="hidden" name="action" value="delete">
            <input type="hidden" name="user_id" value="{u['id']}">
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
      """
    actions_td = action_menu_html(menu_id, menu_items) if not is_current else '<span class="muted" style="font-size:12px;">Active</span>'

    table_rows_html += f"""
        <tr>
            <td>{u['id']}</td>
            <td><strong>{u['username']}</strong></td>
            <td><span class="badge">{u['role'].capitalize()}</span></td>
            <td>{actions_td}</td>
        </tr>
    """

  add_row_html = f"""
        <tr style="background: #f8faf9;">
            <td>#</td>
            <td colspan="3">
                <form method="post" style="display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:8px; align-items:center;">
                    <input type="hidden" name="action" value="add">
                    <input type="text" name="new_username" placeholder="New Username" required maxlength="100" style="padding:8px; margin:0; width:100%; box-sizing:border-box;">
                    <select name="new_role" required style="padding:8px; margin:0; width:100%; box-sizing:border-box;">
                        <option value="protege">Protégé</option>
                        <option value="staff">Staff</option>
                        <option value="admin">Admin</option>
                    </select>
                    <input type="text" name="new_full_name" placeholder="Full name (optional)" style="padding:8px; margin:0; width:100%; box-sizing:border-box;">
                    <div class="password-container" style="margin:0; width:100%;">
                        <input type="password" id="new_user_pass" name="new_password" placeholder="Temporary password (min 8, letter, number, symbol)" required style="padding:8px; padding-right:42px; margin:0; width:100%; box-sizing:border-box;">
                        <button type="button" class="toggle-eye-btn" onclick="togglePasswordVisibility('new_user_pass', this)">
                            <svg viewBox="0 0 24 24"><use href="#icon-eye-open"></use></svg>
                        </button>
                    </div>
                    <button type="submit" class="btn btn-sm" style="margin:0; background:#23594b; white-space:nowrap;">Create Account</button>
                </form>
            </td>
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
                    <th>Action</th>
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
    <p class="muted">Only administrators can create accounts. Choose Admin, Protégé, or Staff; every new account must change its temporary password at first login. Administrators can reset other users’ passwords from Update.</p>
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
    new_password = request.form.get("new_password", "")

    if not updated_username:
      flash("Username is required.")
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
                  "UPDATE users SET username = %s, password = %s, must_change_password = 1 WHERE id = %s",
                  (updated_username, hashed_pw, user_id),
              )
            else:
              db.execute(
                  "UPDATE users SET username = %s WHERE id = %s",
                  (updated_username, user_id),
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

        <p><strong>Role:</strong> {user['role'].capitalize()} (role cannot be changed here)</p>

        <label>Reset Password (Optional)</label>
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

# ---------- ADDITIONAL QSHET MANAGEMENT FEATURES ----------

@app.route("/employees", methods=["GET", "POST"])
def employees():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))
  conn = get_db()
  editing = None
  try:
    with conn.cursor() as db:
      if request.method == "POST":
        action = request.form.get("action", "add")
        if action == "delete":
          employee_id = request.form.get("employee_id", type=int)
          db.execute("SELECT filename FROM employees WHERE id=%s", (employee_id,))
          old = db.fetchone()
          if old:
            db.execute("DELETE FROM employees WHERE id=%s", (employee_id,))
            conn.commit()
            if old.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / old["filename"]).unlink(missing_ok=True)
              except OSError: app.logger.warning("Could not remove employee attachment")
            log_action("delete_employee", str(employee_id))
            flash("Staff profile deleted.")
          return redirect(url_for("employees"))
        employee_id = request.form.get("employee_id", type=int) if action == "edit" else None
        full_name = request.form.get("full_name", "").strip()
        if not full_name:
          flash("Full name is required.")
        else:
          staff_id = request.form.get("staff_id", "").strip() or None
          department = request.form.get("department", "").strip() or None
          position = request.form.get("position", "").strip() or None
          cidb_number = request.form.get("cidb_number", "").strip() or None
          cidb_expiry = request.form.get("cidb_expiry", "").strip() or None
          status = request.form.get("employment_status", "Active")
          if status not in {"Active", "Inactive", "Completed"}: status = "Active"
          try:
            new_file = save_upload(request.files.get("attachment"), "employee")
          except ValueError as exc:
            flash(str(exc)); return redirect(url_for("employees", edit=employee_id) if employee_id else url_for("employees"))
          if employee_id:
            db.execute("SELECT filename FROM employees WHERE id=%s", (employee_id,)); old = db.fetchone()
            if not old:
              flash("Profile not found."); return redirect(url_for("employees"))
            filename = new_file or old.get("filename")
            db.execute("UPDATE employees SET full_name=%s, staff_id=%s, department=%s, position=%s, cidb_number=%s, cidb_expiry=%s, employment_status=%s, filename=%s WHERE id=%s", (full_name, staff_id, department, position, cidb_number, cidb_expiry, status, filename, employee_id))
            conn.commit()
            if new_file and old.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / old["filename"]).unlink(missing_ok=True)
              except OSError: pass
            log_action("edit_employee", full_name); flash("Profile updated successfully.")
          else:
            db.execute("INSERT INTO employees (full_name, staff_id, department, position, cidb_number, cidb_expiry, employment_status, filename) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (full_name, staff_id, department, position, cidb_number, cidb_expiry, status, new_file))
            conn.commit(); log_action("create_employee", full_name); flash("Staff profile created.")
          return redirect(url_for("employees"))
      edit_id = request.args.get("edit", type=int)
      if edit_id:
        db.execute("SELECT * FROM employees WHERE id=%s", (edit_id,)); editing = db.fetchone()
      db.execute("SELECT e.*, u.role FROM employees e LEFT JOIN users u ON e.user_id = u.id ORDER BY e.full_name"); rows = db.fetchall()
  finally:
    conn.close()
  e = editing or {}
  field = lambda name: escape(str(e.get(name) or ""))
  selected = lambda val: "selected" if e.get("employment_status", "Active") == val else ""
  
  def build_employee_table(filtered_rows):
    t_html = "<div class='table-wrap'><table><thead><tr><th>Name</th><th>Staff ID</th><th>Department</th><th>Position</th><th>CIDB No.</th><th>CIDB expiry</th><th>Status</th><th>Action</th></tr></thead><tbody>"
    if filtered_rows:
      for r in filtered_rows:
        menu_id = f"emp_menu_{r['id']}"
        menu_items = f"""
            <a href='/employees?edit={r['id']}'>
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
            </a>
            <form method='post' onsubmit="return confirm('Delete this profile?')" style="margin:0;">
                <input type='hidden' name='action' value='delete'>
                <input type='hidden' name='employee_id' value='{r['id']}'>
                <button type="submit" class="text-danger">
                    <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
                </button>
            </form>
        """
        actions_td = action_menu_html(menu_id, menu_items)
        file_view = f"<a target='_blank' href='/uploads/{quote(str(r['filename']), safe='')}'>View file</a><br>" if r.get('filename') else ''
        t_html += f"<tr><td>{escape(str(r['full_name'] or ''))}</td><td>{escape(str(r['staff_id'] or '-'))}</td><td>{escape(str(r['department'] or '-'))}</td><td>{escape(str(r['position'] or '-'))}</td><td>{escape(str(r['cidb_number'] or '-'))}</td><td>{escape(str(r['cidb_expiry'] or '-'))}</td><td>{escape(str(r['employment_status'] or ''))}</td><td>{file_view}{actions_td}</td></tr>"
    else:
      t_html += "<tr><td colspan='8' class='muted'>No profiles found.</td></tr>"
    t_html += "</tbody></table></div>"
    return t_html

  # AFTER (Flexible check matching Position title or User Role or Staff ID):
  protege_profiles = []
  staff_profiles = []

  for r in rows:
    pos = (r.get('position') or '').lower()
    role = (r.get('role') or '').lower()
    staff_id = (r.get('staff_id') or '').upper()

    # Detect if record represents a Protégé
    if 'protege' in pos or 'protégé' in pos or role == 'protege' or staff_id.startswith('PROTÉGÉ') or staff_id.startswith('PROTEGE'):
        protege_profiles.append(r)
    else:
        staff_profiles.append(r)

  content = f"""
    <h2>Staff & Protégé Profiles</h2>
    <section class='panel'>
      <h3>{'Edit profile' if editing else 'Add profile'}</h3>
      <form method='post' enctype='multipart/form-data'>
        <input type='hidden' name='action' value="{'edit' if editing else 'add'}">
        <input type='hidden' name='employee_id' value='{e.get('id','') if editing else ''}'>
        <label>Full name</label><input name='full_name' required maxlength='150' value='{field('full_name')}'>
        <label>Staff ID</label><input name='staff_id' maxlength='80' value='{field('staff_id')}'>
        <label>Department</label><input name='department' maxlength='100' value='{field('department')}'>
        <label>Position</label><input name='position' maxlength='100' value='{field('position')}'>
        <label>CIDB number</label><input name='cidb_number' maxlength='100' value='{field('cidb_number')}'>
        <label>CIDB expiry date</label><input type='date' name='cidb_expiry' value='{field('cidb_expiry')}'>
        <label>Status</label><select name='employment_status'><option {selected('Active')}>Active</option><option {selected('Inactive')}>Inactive</option><option {selected('Completed')}>Completed</option></select>
        <label>Attach Certificate / File (Optional)<br><span style="font-size: 12px; font-weight: normal; color: #7a8c83;">Supported formats: PDF, JPG, PNG</span></label>
        <input type="file" name="attachment" accept=".png, .jpg, .jpeg, .pdf">
        {'<p class="muted">An existing attachment will be kept if no new file is selected.</p>' if editing and e.get('filename') else ''}
        <button>{'Save Changes' if editing else 'Add Profile'}</button> {'<a class="btn" href="/employees">Cancel</a>' if editing else ''}
      </form>
    </section>
    <section class='panel'>
      <h3>Protégé Profiles</h3>
      {build_employee_table(protege_profiles)}
    </section>
    <section class='panel'>
      <h3>Staff Profiles</h3>
      {build_employee_table(staff_profiles)}
    </section>
  """
  return page(content)


@app.route("/actions", methods=["GET", "POST"])
def actions():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))
  conn = get_db(); editing = None
  try:
    with conn.cursor() as db:
      if request.method == "POST":
        action = request.form.get("action", "add")
        aid = request.form.get("action_id", type=int)
        if action == "delete":
          db.execute("SELECT filename FROM corrective_actions WHERE id=%s", (aid,)); old = db.fetchone()
          if old:
            db.execute("DELETE FROM corrective_actions WHERE id=%s", (aid,)); conn.commit()
            if old.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / old["filename"]).unlink(missing_ok=True)
              except OSError: pass
            log_action("delete_corrective_action", str(aid)); flash("Corrective action deleted.")
          return redirect(url_for("actions"))
        title = request.form.get("title", "").strip()
        if not title:
          flash("Action title is required.")
        else:
          try: new_file = save_upload(request.files.get("attachment"), "action")
          except ValueError as exc:
            flash(str(exc)); return redirect(url_for("actions", edit=aid) if action == "edit" else url_for("actions"))
          description = request.form.get("description", "").strip()
          source_type = request.form.get("source_type", "General")
          if source_type not in {"Incident", "Inspection", "Audit", "General"}: source_type = "General"
          severity = request.form.get("severity", "Medium")
          if severity not in {"Low", "Medium", "High", "Critical"}: severity = "Medium"
          due = request.form.get("due_date", "").strip() or None
          assigned = request.form.get("assigned_to", "").strip() or None
          location = request.form.get("location", "").strip() or None
          if action == "edit" and aid:
            db.execute("SELECT filename FROM corrective_actions WHERE id=%s", (aid,)); old = db.fetchone()
            if not old: flash("Corrective action not found."); return redirect(url_for("actions"))
            filename = new_file or old.get("filename")
            status = request.form.get("status", "Open")
            if status not in {"Open", "In Progress", "Resolved", "Closed"}: status = "Open"
            notes = request.form.get("resolution_notes", "").strip()
            db.execute("UPDATE corrective_actions SET title=%s, description=%s, source_type=%s, location=%s, severity=%s, assigned_to=%s, due_date=%s, status=%s, resolution_notes=%s, resolved_at=IF(%s IN ('Resolved','Closed'), COALESCE(resolved_at,NOW()), NULL), filename=%s WHERE id=%s", (title, description, source_type, location, severity, assigned, due, status, notes, status, filename, aid))
            conn.commit()
            if new_file and old.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / old["filename"]).unlink(missing_ok=True)
              except OSError: pass
            log_action("edit_corrective_action", title); flash("Corrective action updated.")
          else:
            db.execute("INSERT INTO corrective_actions (title, description, source_type, location, severity, assigned_to, due_date, status, filename) VALUES (%s,%s,%s,%s,%s,%s,%s,'Open',%s)", (title, description, source_type, location, severity, assigned, due, new_file))
            conn.commit(); log_action("create_corrective_action", title); flash("Corrective action added.")
          return redirect(url_for("actions"))
      edit_id = request.args.get("edit", type=int)
      if edit_id: db.execute("SELECT * FROM corrective_actions WHERE id=%s", (edit_id,)); editing = db.fetchone()
      db.execute("SELECT * FROM corrective_actions ORDER BY (status IN ('Resolved','Closed')), due_date IS NULL, due_date, id DESC"); rows = db.fetchall()
  finally: conn.close()
  e = editing or {}; field = lambda name: escape(str(e.get(name) or ""))
  opts = lambda name, values, default: "".join(f"<option {'selected' if e.get(name, default)==v else ''}>{v}</option>" for v in values)
  
  tr_list = []
  for r in rows:
    menu_id = f"action_menu_{r['id']}"
    menu_items = f"""
        <a href='/actions?edit={r['id']}'>
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
        </a>
        <form method='post' onsubmit="return confirm('Delete this action?')" style="margin:0;">
            <input type='hidden' name='action' value='delete'>
            <input type='hidden' name='action_id' value='{r['id']}'>
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
    """
    actions_td = action_menu_html(menu_id, menu_items)
    file_view = f"<a target='_blank' href='/uploads/{quote(str(r['filename']), safe='')}'>View file</a><br>" if r.get('filename') else ''
    
    tr_list.append(f"<tr><td>{escape(str(r['title'] or ''))}</td><td>{escape(str(r['source_type'] or ''))}</td><td>{escape(str(r['location'] or '-'))}</td><td>{escape(str(r['severity'] or ''))}</td><td>{escape(str(r['assigned_to'] or '-'))}</td><td>{escape(str(r['due_date'] or '-'))}</td><td>{escape(str(r['status'] or ''))}</td><td>{file_view}{actions_td}</td></tr>")
  
  tr = "".join(tr_list) or "<tr><td colspan='8'>No corrective actions yet.</td></tr>"

  content = f"""<h2>Corrective Actions & Follow-up</h2><section class='panel'><h3>{'Edit corrective action' if editing else 'Create action'}</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='action' value="{'edit' if editing else 'add'}"><input type='hidden' name='action_id' value="{e.get('id','') if editing else ''}">
  <label>Action title</label><input name='title' required maxlength='180' value='{field('title')}'><label>Description</label><textarea name='description' rows='3'>{field('description')}</textarea>
  <label>Source</label><select name='source_type'>{opts('source_type',['Incident','Inspection','Audit','General'],'General')}</select><label>Location / site</label><input name='location' value='{field('location')}'><label>Severity</label><select name='severity'>{opts('severity',['Low','Medium','High','Critical'],'Medium')}</select>
  <label>Person responsible</label><input name='assigned_to' value='{field('assigned_to')}'><label>Due date</label><input type='date' name='due_date' value='{field('due_date')}'><label>Status</label><select name='status'>{opts('status',['Open','In Progress','Resolved','Closed'],'Open')}</select><label>Resolution notes</label><textarea name='resolution_notes' rows='2'>{field('resolution_notes')}</textarea>
  <label>Attach Certificate / File (Optional)<br><span style="font-size: 12px; font-weight: normal; color: #7a8c83;">Supported formats: PDF, JPG, PNG</span></label>
  <input type="file" name="attachment" accept=".png, .jpg, .jpeg, .pdf">
  <button>{'Save Changes' if editing else 'Save Action'}</button> {'<a class="btn" href="/actions">Cancel</a>' if editing else ''}</form></section><section class='panel'><h3>Corrective Actions</h3><div class='table-wrap'><table><thead><tr><th>Title</th><th>Source</th><th>Location</th><th>Severity</th><th>Assigned To</th><th>Due Date</th><th>Status</th><th>Action</th></tr></thead><tbody>{tr}</tbody></table></div></section>"""
  return page(content)


@app.route("/inspections", methods=["GET", "POST"])
def inspections():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))
  conn = get_db(); editing = None
  try:
    with conn.cursor() as db:
      if request.method == "POST":
        action = request.form.get("action", "add"); iid = request.form.get("inspection_id", type=int)
        if action == "delete":
          db.execute("SELECT filename FROM inspections WHERE id=%s", (iid,)); old = db.fetchone()
          if old:
            db.execute("DELETE FROM inspections WHERE id=%s", (iid,)); conn.commit()
            if old.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / old["filename"]).unlink(missing_ok=True)
              except OSError: pass
            log_action("delete_inspection", str(iid)); flash("Inspection deleted.")
          return redirect(url_for("inspections"))
        site = request.form.get("site_name", "").strip(); inspector = request.form.get("inspector", "").strip(); item = request.form.get("checklist_item", "").strip()
        if not site or not inspector or not item:
          flash("Site, inspector and checklist item are required.")
        else:
          try: new_file = save_upload(request.files.get("attachment"), "inspection")
          except ValueError as exc:
            flash(str(exc)); return redirect(url_for("inspections", edit=iid) if action == "edit" else url_for("inspections"))
          insp_date = request.form.get("inspection_date") or date.today().isoformat(); due = request.form.get("due_date", "").strip() or None
          result = request.form.get("result", "Pass")
          if result not in {"Pass", "Fail", "Observation", "Not Applicable"}: result = "Pass"
          status = request.form.get("status", "Open")
          if status not in {"Open", "In Progress", "Closed"}: status = "Open"
          findings = request.form.get("findings", "").strip(); corrective = request.form.get("corrective_action", "").strip(); assigned = request.form.get("assigned_to", "").strip() or None
          if action == "edit" and iid:
            db.execute("SELECT filename FROM inspections WHERE id=%s", (iid,)); old = db.fetchone()
            if not old: flash("Inspection not found."); return redirect(url_for("inspections"))
            filename = new_file or old.get("filename")
            db.execute("UPDATE inspections SET site_name=%s, inspection_date=%s, inspector=%s, checklist_item=%s, result=%s, findings=%s, corrective_action=%s, assigned_to=%s, due_date=%s, status=%s, filename=%s WHERE id=%s", (site, insp_date, inspector, item, result, findings, corrective, assigned, due, status, filename, iid))
            conn.commit()
            if new_file and old.get("filename"):
              try: (app.config["UPLOAD_FOLDER"] / old["filename"]).unlink(missing_ok=True)
              except OSError: pass
            log_action("edit_inspection", f"{site}: {item}"); flash("Inspection updated.")
          else:
            status = "Open" if result in {"Fail", "Observation"} else "Closed"
            db.execute("INSERT INTO inspections (site_name, inspection_date, inspector, checklist_item, result, findings, corrective_action, assigned_to, due_date, status, filename) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (site, insp_date, inspector, item, result, findings, corrective, assigned, due, status, new_file))
            conn.commit(); log_action("create_inspection", f"{site}: {item} - {result}"); flash("Inspection finding saved.")
          return redirect(url_for("inspections"))
      edit_id = request.args.get("edit", type=int)
      if edit_id: db.execute("SELECT * FROM inspections WHERE id=%s", (edit_id,)); editing = db.fetchone()
      db.execute("SELECT * FROM inspections ORDER BY inspection_date DESC, id DESC"); rows = db.fetchall()
  finally: conn.close()
  e = editing or {}; field = lambda name: escape(str(e.get(name) or ""))
  opts = lambda name, values, default: "".join(f"<option {'selected' if e.get(name, default)==v else ''}>{v}</option>" for v in values)
  
  tr_list = []
  for r in rows:
    menu_id = f"insp_menu_{r['id']}"
    menu_items = f"""
        <a href='/inspections?edit={r['id']}'>
            <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-edit-pencil"></use></svg> Edit
        </a>
        <form method='post' onsubmit="return confirm('Delete this inspection?')" style="margin:0;">
            <input type='hidden' name='action' value='delete'>
            <input type='hidden' name='inspection_id' value='{r['id']}'>
            <button type="submit" class="text-danger">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2" fill="none"><use href="#icon-trash"></use></svg> Delete
            </button>
        </form>
    """
    actions_td = action_menu_html(menu_id, menu_items)
    file_view = f"<a target='_blank' href='/uploads/{quote(str(r['filename']), safe='')}'>View file</a><br>" if r.get('filename') else ''
    
    tr_list.append(f"<tr><td>{escape(str(r['inspection_date'] or ''))}</td><td>{escape(str(r['site_name'] or ''))}</td><td>{escape(str(r['inspector'] or ''))}</td><td>{escape(str(r['checklist_item'] or ''))}</td><td>{escape(str(r['result'] or ''))}</td><td>{escape(str(r['findings'] or '-'))}</td><td>{escape(str(r['assigned_to'] or '-'))}</td><td>{escape(str(r['due_date'] or '-'))}</td><td>{escape(str(r['status'] or ''))}</td><td>{file_view}{actions_td}</td></tr>")
  
  tr = "".join(tr_list) or "<tr><td colspan='10'>No inspections recorded yet.</td></tr>"

  content = f"""<h2>Site Inspection Checklist</h2><section class='panel'><h3>{'Edit inspection' if editing else 'Record inspection item'}</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='action' value="{'edit' if editing else 'add'}"><input type='hidden' name='inspection_id' value="{e.get('id','') if editing else ''}">
  <label>Site / project</label><input name='site_name' required value='{field('site_name')}'><label>Inspection date</label><input type='date' name='inspection_date' value='{field('inspection_date') or date.today().isoformat()}' required><label>Inspector</label><input name='inspector' required value='{field('inspector')}'><label>Checklist item</label><input name='checklist_item' required value='{field('checklist_item')}'><label>Result</label><select name='result'>{opts('result',['Pass','Fail','Observation','Not Applicable'],'Pass')}</select><label>Findings / notes</label><textarea name='findings' rows='3'>{field('findings')}</textarea><label>Corrective action required</label><textarea name='corrective_action' rows='2'>{field('corrective_action')}</textarea><label>Assigned to</label><input name='assigned_to' value='{field('assigned_to')}'><label>Due date</label><input type='date' name='due_date' value='{field('due_date')}'><label>Status</label><select name='status'>{opts('status',['Open','In Progress','Closed'],'Open')}</select>
  <label>Attach Certificate / File (Optional)<br><span style="font-size: 12px; font-weight: normal; color: #7a8c83;">Supported formats: PDF, JPG, PNG</span></label>
  <input type="file" name="attachment" accept=".png, .jpg, .jpeg, .pdf">
  <button>{'Save Changes' if editing else 'Save Inspection'}</button> {'<a class="btn" href="/inspections">Cancel</a>' if editing else ''}</form></section><section class='panel'><h3>Inspection register</h3><div class='table-wrap'><table><thead><tr><th>Date</th><th>Site</th><th>Inspector</th><th>Checklist item</th><th>Result</th><th>Findings</th><th>Assigned to</th><th>Due date</th><th>Status</th><th>Action</th></tr></thead><tbody>{tr}</tbody></table></div></section>"""
  return page(content)


@app.route("/reports")
def reports():
  if session.get("role") != "admin":
    flash("Access denied. Admin only.")
    return redirect(url_for("dashboard"))
    
  filter_type = request.args.get("filter", "all")
  start_date = request.args.get("start_date", "")
  end_date = request.args.get("end_date", "")

  date_condition = "1=1"
  params = []
  today = date.today()

  if filter_type == "week":
    start_date_val = today - timedelta(days=7)
    date_condition = "created_at >= %s"
    params = [start_date_val]
  elif filter_type == "month":
    start_date_val = today - timedelta(days=30)
    date_condition = "created_at >= %s"
    params = [start_date_val]
  elif filter_type == "custom" and start_date and end_date:
    try:
      parsed_start = date.fromisoformat(start_date)
      parsed_end = date.fromisoformat(end_date)
      if parsed_end < parsed_start:
        raise ValueError("End date must not be earlier than start date.")
      date_condition = "created_at BETWEEN %s AND %s"
      params = [parsed_start.isoformat(), parsed_end.isoformat() + " 23:59:59"]
    except ValueError:
      flash("Please provide a valid date range.")
      filter_type, start_date, end_date = "all", "", ""

  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT status, COUNT(*) AS total FROM safety_reports GROUP BY status")
      safety_counts = db.fetchall()
      
      db.execute("SELECT COUNT(*) AS total FROM corrective_actions WHERE status NOT IN ('Resolved','Closed')")
      open_actions = db.fetchone()["total"]
      
      db.execute("SELECT COUNT(*) AS total FROM inspections WHERE result IN ('Fail','Observation')")
      inspection_issues = db.fetchone()["total"]

      log_query = f"SELECT id, username, action, details, created_at FROM audit_logs WHERE {date_condition} ORDER BY id DESC LIMIT 200"
      db.execute(log_query, params)
      logs = db.fetchall()

      db.execute("SELECT expiry_date AS expiry FROM training WHERE expiry_date IS NOT NULL AND expiry_date <> '' UNION ALL SELECT review_date AS expiry FROM documents WHERE review_date IS NOT NULL AND review_date <> ''")
      dates = db.fetchall()
  finally: 
    conn.close()

  soon = today + timedelta(days=30)
  expired = 0
  expiring = 0
  for row in dates:
    try:
      d = date.fromisoformat(str(row["expiry"])[:10])
      if d < today: expired += 1
      elif d <= soon: expiring += 1
    except (ValueError, TypeError): 
      pass

  safety_html = "".join(
      f"<li>{escape(r['status'] or '')}: <strong>{int(r['total'] or 0)}</strong></li>"
      for r in safety_counts
  ) or "<li>No safety reports.</li>"
  logs_html = "".join(
      f"<tr><td>{escape(r['created_at'] or '')}</td>"
      f"<td>{escape(r['username'] or 'System')}</td>"
      f"<td>{escape(r['action'] or '')}</td>"
      f"<td>{escape(r['details'] or '-')}</td></tr>"
      for r in logs
  ) or "<tr><td colspan='4'>No audit entries found for this period.</td></tr>"

  filter_form_html = f"""
    <section class='panel'>
      <h3>Filter Audit Log & Reports</h3>
      <form method='get' action='/reports' style='display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end;'>
        <div>
          <label style='margin-bottom:4px;'>View Mode</label>
          <select name='filter' onchange='this.form.submit()' style='padding: 8px; border-radius: 8px;'>
            <option value='all' {'selected' if filter_type=='all' else ''}>All Time</option>
            <option value='week' {'selected' if filter_type=='week' else ''}>Past Week (Weekly Summary)</option>
            <option value='month' {'selected' if filter_type=='month' else ''}>Past Month (Monthly Summary)</option>
            <option value='custom' {'selected' if filter_type=='custom' else ''}>Custom Date Range</option>
          </select>
        </div>
        <div id='custom_dates' style='display: {'flex' if filter_type=='custom' else 'none'}; gap: 10px; align-items: flex-end;'>
          <div>
            <label style='margin-bottom:4px;'>Start Date</label>
            <input type='date' name='start_date' value='{start_date}' style='padding: 6px;'>
          </div>
          <div>
            <label style='margin-bottom:4px;'>End Date</label>
            <input type='date' name='end_date' value='{end_date}' style='padding: 6px;'>
          </div>
          <button type='submit' class='btn btn-sm' style='margin-top: 0;'>Apply</button>
        </div>
      </form>
    </section>
  """

  content = f"""
    <h2>Reports & Audit Log</h2>
    {filter_form_html}
    <div class='cards'>
      <div class='card'>Expired training/document dates<div class='number'>{expired}</div></div>
      <div class='card'>Due within 30 days<div class='number'>{expiring}</div></div>
      <div class='card'>Open corrective actions<div class='number'>{open_actions}</div></div>
      <div class='card'>Inspection findings<div class='number'>{inspection_issues}</div></div>
    </div>
    <section class='panel'>
      <h3>Safety report status</h3>
      <ul>{safety_html}</ul>
      <p class='muted'>Use the browser's Print option to save this page as PDF. Date alerts are based on existing date fields; check source records for invalid legacy dates.</p>
      <button onclick='window.print()'>Print / Save PDF</button>
    </section>
    <section class='panel'>
      <h3>Audit Activity Log</h3>
      <div class='table-wrap'>
        <table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>{logs_html}</tbody>
        </table>
      </div>
    </section>
  """
  return page(content)


@app.route("/uploads/<filename>")
def uploaded_file(filename):
  filename = Path(str(filename or "")).name
  if not filename or filename in {".", ".."}:
    return "Invalid file name", 400
  if "user_id" not in session:
    return redirect(url_for("login"))
  if session.get("role") == "admin":
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)
  conn = get_db()
  try:
    with conn.cursor() as db:
      db.execute("SELECT id FROM cidb_uploads WHERE filename = %s AND user_id = %s", (filename, session["user_id"]))
      allowed = db.fetchone()
      if not allowed:
        db.execute("SELECT id FROM protege_safety_submissions WHERE filename = %s AND user_id = %s", (filename, session["user_id"]))
        allowed = db.fetchone()
      if not allowed:
        db.execute("SELECT full_name FROM employees WHERE user_id=%s LIMIT 1", (session["user_id"],))
        employee = db.fetchone()
        names = [session.get("username", "")]
        if employee and employee.get("full_name"):
          names.append(employee["full_name"])
        placeholders = ",".join(["%s"] * len(names))
        db.execute(f"SELECT id FROM training WHERE filename=%s AND employee IN ({placeholders})", (filename, *names))
        allowed = db.fetchone()
  finally:
    conn.close()
  if not allowed:
    return "Access denied", 403
  return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)



# ============================================================================
# QSHET RELIABILITY ENHANCEMENTS
# ============================================================================

import hmac
import threading
import time
from collections import defaultdict, deque

_CONFIGURED_SECRET = os.environ.get("FLASK_SECRET_KEY")
if os.environ.get("APP_ENV", "").lower() == "production" and not _CONFIGURED_SECRET:
    raise RuntimeError("Set FLASK_SECRET_KEY before running QSHET in production.")
if _CONFIGURED_SECRET:
    app.secret_key = _CONFIGURED_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
)

_werkzeug_secure_filename = secure_filename

def secure_filename(filename):
    cleaned = _werkzeug_secure_filename(str(filename or ""))
    if not cleaned:
        return f"upload_{uuid.uuid4().hex}"
    path = Path(cleaned)
    return f"{path.stem[:150]}_{uuid.uuid4().hex[:12]}{path.suffix.lower()}"


def valid_upload_file(file_storage):
    if not file_storage or not getattr(file_storage, "filename", ""):
        return False
    original = _werkzeug_secure_filename(file_storage.filename)
    extension = Path(original).suffix.lower()
    if extension not in {".pdf", ".png", ".jpg", ".jpeg"}:
        return False
    stream = getattr(file_storage, "stream", None)
    if stream is None:
        return False
    try:
        position = stream.tell()
        header = stream.read(16)
        stream.seek(position)
    except (OSError, AttributeError, ValueError):
        return False
    if extension == ".pdf":
        return header.startswith(b"%PDF-")
    if extension == ".png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if extension in {".jpg", ".jpeg"}:
        return header.startswith(b"\xff\xd8\xff")
    return False


def save_upload(file, prefix="file"):
    if not file or not file.filename:
        return None
    if not valid_upload_file(file):
        raise ValueError("The file content does not match an allowed PDF, JPG, JPEG or PNG file.")
    original = _werkzeug_secure_filename(file.filename)
    suffix = Path(original).suffix.lower()
    filename = f"{_werkzeug_secure_filename(prefix)[:30]}_{uuid.uuid4().hex}{suffix}"
    destination = app.config["UPLOAD_FOLDER"] / filename
    file.save(destination)
    return filename

_CSRF_FORM_TOKEN = "_csrf_token"
_POST_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_LOGIN_ATTEMPTS = defaultdict(deque)
_LOGIN_ATTEMPTS_LOCK = threading.Lock()
_LOGIN_WINDOW_SECONDS = 15 * 60
_LOGIN_MAX_ATTEMPTS = 10

@app.before_request
def qshet_security_guard():
    token = session.get(_CSRF_FORM_TOKEN)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_FORM_TOKEN] = token

    if request.endpoint == "login" and request.method == "POST":
        now = time.time()
        client = request.remote_addr or "unknown"
        with _LOGIN_ATTEMPTS_LOCK:
            attempts = _LOGIN_ATTEMPTS[client]
            while attempts and now - attempts[0] > _LOGIN_WINDOW_SECONDS:
                attempts.popleft()
            if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
                return ("Too many login attempts. Please wait 15 minutes and try again.", 429)
            attempts.append(now)

    if request.method == "POST":
        supplied = request.form.get(_CSRF_FORM_TOKEN) or request.headers.get("X-CSRF-Token", "")
        if not supplied or not hmac.compare_digest(str(token), str(supplied)):
            return ("The form security token is missing or expired. Reload the page and try again.", 400)

@app.after_request
def qshet_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if response.mimetype == "text/html":
        response.headers.setdefault("Cache-Control", "no-store")
        token = str(session.get(_CSRF_FORM_TOKEN, ""))
        if token and response.get_data():
            html = response.get_data(as_text=True)
            def add_token(match):
                tag = match.group(0)
                if not re.search(r"\bmethod\s*=\s*(['\"]?)post\1", tag, re.IGNORECASE):
                    return tag
                if re.search(r"name\s*=\s*(['\"]?)_csrf_token\1", tag, re.IGNORECASE):
                    return tag
                return tag + f'<input type="hidden" name="{_CSRF_FORM_TOKEN}" value="{token}">'
            response.set_data(_POST_FORM_RE.sub(add_token, html))
    return response


def _parse_qshet_date(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    raw = str(value).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw[:10], fmt).date()
        except ValueError:
            continue
    return None


def _alert_row(label, title, due_date, detail, url="#"):
    due = _parse_qshet_date(due_date)
    if not due:
        return None
    today = date.today()
    days = (due - today).days
    if days > 30:
        return None
    if days < 0:
        timing = f"Overdue by {abs(days)} day(s)"
        color = "#c85a54"
    elif days == 0:
        timing = "Due today"
        color = "#c85a54"
    else:
        timing = f"Due in {days} day(s)"
        color = "#dfa85b"
    return (
        f"<tr><td>{escape(label)}</td><td>{escape(title)}</td>"
        f"<td>{escape(due.strftime('%d %b %Y'))}</td>"
        f"<td><strong style='color:{color}'>{escape(timing)}</strong></td>"
        f"<td>{escape(detail or '—')}</td><td>{url}</td></tr>"
    )

@app.route("/alerts", methods=["GET", "POST"])
def qshet_alerts():
    if session.get("role") != "admin":
        flash("Access denied. Admin only.")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        if request.form.get("action") != "create_action":
            flash("Unsupported alert action.")
            return redirect(url_for("qshet_alerts"))
        inspection_id = request.form.get("inspection_id", type=int)
        if not inspection_id:
            flash("Invalid inspection reference.")
            return redirect(url_for("qshet_alerts"))
        conn = get_db()
        try:
            with conn.cursor() as db:
                db.execute("SELECT * FROM inspections WHERE id=%s", (inspection_id,))
                inspection = db.fetchone()
                if not inspection:
                    flash("Inspection was not found.")
                elif inspection.get("result") not in {"Fail", "Observation"}:
                    flash("Only failed or observation findings can become corrective actions.")
                else:
                    db.execute("SELECT id FROM corrective_actions WHERE source_type='Inspection' AND source_id=%s LIMIT 1", (inspection_id,))
                    existing = db.fetchone()
                    if existing:
                        flash(f"This inspection already links to corrective action #{existing['id']}.")
                    else:
                        severity = "High" if inspection.get("result") == "Fail" else "Medium"
                        title = f"Inspection finding: {inspection.get('checklist_item') or 'Untitled finding'}"
                        description = inspection.get("findings") or inspection.get("corrective_action") or "Follow up on the inspection finding."
                        db.execute(
                            """INSERT INTO corrective_actions
                               (title, description, source_type, source_id, location, severity,
                                assigned_to, due_date, status)
                               VALUES (%s,%s,'Inspection',%s,%s,%s,%s,%s,'Open')""",
                            (title[:180], description, inspection_id, inspection.get("site_name"), severity,
                             inspection.get("assigned_to"), inspection.get("due_date")),
                        )
                        conn.commit()
                        log_action("create_action_from_inspection", f"Inspection #{inspection_id}")
                        flash("Corrective action created and linked to the inspection.")
        except Exception:
            conn.rollback()
            app.logger.exception("Could not create corrective action from inspection")
            flash("The corrective action could not be created. Please try again or contact the system administrator.")
        finally:
            conn.close()
        return redirect(url_for("qshet_alerts"))

    conn = get_db()
    alert_rows = []
    try:
        with conn.cursor() as db:
            db.execute("SELECT id,title,due_date,status,severity,assigned_to FROM corrective_actions WHERE status NOT IN ('Resolved','Closed') AND due_date IS NOT NULL")
            for row in db.fetchall():
                rendered = _alert_row("Corrective action", row.get("title"), row.get("due_date"), f"{row.get('severity') or 'Medium'} · {row.get('status') or 'Open'} · {row.get('assigned_to') or 'Unassigned'}", f"<a href='/actions?edit={int(row['id'])}'>Open</a>")
                if rendered: alert_rows.append(rendered)

            db.execute("SELECT id,site_name,checklist_item,inspection_date,result,findings,due_date,status FROM inspections WHERE status <> 'Closed' AND due_date IS NOT NULL")
            for row in db.fetchall():
                action_button = "—"
                if row.get("result") in {"Fail", "Observation"}:
                    action_button = (f"<form method='post' style='margin:0'><input type='hidden' name='action' value='create_action'>"
                                     f"<input type='hidden' name='inspection_id' value='{int(row['id'])}'>"
                                     f"<button class='btn-sm' type='submit'>Create corrective action</button></form>")
                rendered = _alert_row("Inspection", f"{row.get('site_name')}: {row.get('checklist_item')}", row.get("due_date"), f"{row.get('result')} · {row.get('status')}", action_button)
                if rendered: alert_rows.append(rendered)

            db.execute("SELECT id,title,review_date FROM documents WHERE review_date IS NOT NULL AND review_date <> ''")
            for row in db.fetchall():
                rendered = _alert_row("Document review", row.get("title"), row.get("review_date"), "Review date")
                if rendered: alert_rows.append(rendered)

            db.execute("SELECT id,employee,course,expiry_date FROM training WHERE expiry_date IS NOT NULL AND expiry_date <> ''")
            for row in db.fetchall():
                rendered = _alert_row("Training expiry", f"{row.get('employee')}: {row.get('course')}", row.get("expiry_date"), "Certificate expiry")
                if rendered: alert_rows.append(rendered)

            db.execute("SELECT id,full_name,cidb_number,cidb_expiry,employment_status FROM employees WHERE cidb_expiry IS NOT NULL AND employment_status='Active'")
            for row in db.fetchall():
                rendered = _alert_row("Staff/Employee CIDB", f"{row.get('full_name')} ({row.get('cidb_number') or 'No CIDB number'})", row.get("cidb_expiry"), "Active profile")
                if rendered: alert_rows.append(rendered)
    except Exception:
        app.logger.exception("Could not load QSHET alerts")
        flash("Some alerts could not be loaded. Check the application log and database connection.")
    finally:
        conn.close()

    alert_rows.sort(key=lambda row: row.lower().find("overdue") if "overdue" in row.lower() else 999999)
    body = "".join(alert_rows) or "<tr><td colspan='6' class='muted'>No overdue or upcoming items found within the next 30 days.</td></tr>"
    content = f"""
      <h2>QSHET Alerts & Upcoming Deadlines</h2>
      <p class='muted'>This page highlights overdue items and items due within 30 days. Confirm the source record before taking action.</p>
      <section class='panel'><div class='table-wrap'><table>
        <thead><tr><th>Record type</th><th>Record</th><th>Due date</th><th>Alert</th><th>Details</th><th>Action</th></tr></thead>
        <tbody>{body}</tbody>
      </table></div></section>
    """
    return page(content)


@app.errorhandler(413)
def qshet_file_too_large(_error):
  flash("The selected file is larger than the 10 MB upload limit.")
  return ("The selected file is too large. Maximum upload size is 10 MB.", 413)


@app.errorhandler(500)
def qshet_internal_error(error):
  app.logger.error("Unhandled QSHET application error: %s", error, exc_info=True)
  return ("An unexpected system error occurred. Please contact the QSHET administrator.", 500)


if __name__ == "__main__":
  init_db()
  app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1", host=os.environ.get("FLASK_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")))
