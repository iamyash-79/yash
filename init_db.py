import sqlite3

conn = sqlite3.connect('catalog.db')  # replace with your actual DB file
conn.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0;")
conn.commit()
conn.close()
