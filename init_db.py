import sqlite3

# Connect to (or create) the database
conn = sqlite3.connect('user.db')
cur = conn.cursor()

# Create the users table
cur.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    mobile TEXT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    profile_image TEXT,
    role TEXT NOT NULL DEFAULT 'user'
)
''')

conn.commit()
conn.close()

print("Database initialized successfully.")
