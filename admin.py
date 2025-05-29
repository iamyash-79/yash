import sqlite3
from werkzeug.security import generate_password_hash

# ✅ CHANGE THESE:
first_name = "Admin"
last_name = ""
mobile = "7987190554"
email = "admin@example.co"  # NEW ADMIN EMAIL
password = "admin@example.co"       # NEW ADMIN PASSWORD
role = "admin"

# Hash the password
hashed_pw = generate_password_hash(password)

# Connect to DB
conn = sqlite3.connect('user.db')
cur = conn.cursor()

# Check if admin exists
existing = cur.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()

if existing:
    cur.execute('''
        UPDATE users SET first_name = ?, last_name = ?, mobile = ?, password = ?, role = ?
        WHERE email = ?
    ''', (first_name, last_name, mobile, hashed_pw, role, email))
    print(f"🔁 Admin '{email}' updated successfully.")
else:
    cur.execute('''
        INSERT INTO users (first_name, last_name, mobile, email, password, role)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, mobile, email, hashed_pw, role))
    print(f"✅ Admin '{email}' created successfully.")

conn.commit()
conn.close()
