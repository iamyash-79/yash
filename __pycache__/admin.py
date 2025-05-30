import sqlite3
from werkzeug.security import generate_password_hash

# Admin user details
first_name = "Admin"
last_name = ""
mobile = "9999999999"
email = "admin@example.co"
password = "admin@example.co"  # You can change this
role = "admin"

# Hash the password
hashed_pw = generate_password_hash(password)

# Insert into DB
conn = sqlite3.connect('user.db')
cur = conn.cursor()

try:
    cur.execute('''
        INSERT INTO users (first_name, last_name, mobile, email, password, role)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (first_name, last_name, mobile, email, hashed_pw, role))
    conn.commit()
    print(f"✅ Admin user '{email}' added successfully.")
except sqlite3.IntegrityError:
    print(f"⚠️ Email '{email}' already exists in the database.")
finally:
    conn.close()
