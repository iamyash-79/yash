from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_db():
    conn = sqlite3.connect('user.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_catalog_db():
    conn = sqlite3.connect('catalog.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user():
    if "user" not in session:
        return None
    conn = get_user_db()
    row = conn.execute(
        "SELECT first_name, last_name, email, profile_image, role, mobile FROM users WHERE email = ?",
        (session["user"],)
    ).fetchone()
    conn.close()
    if row:
        return {
            "name": f"{row['first_name']} {row['last_name']}",
            "first_name": row['first_name'],
            "last_name": row['last_name'],
            "email": row['email'],
            "profile_image": row['profile_image'],
            "role": row['role'],
            "contact": row['mobile'],
            "short_name": row['first_name']
        }
    return None

@app.route("/")
@app.route("/home")
def home():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_catalog_db()
    cursor = conn.execute("SELECT id, name, price, discount_price, images FROM catalog")
    catalog_items = [
        {
            'id': row['id'],
            'name': row['name'],
            'price': row['price'],
            'discount_price': row['discount_price'],
            'images': row['images'].split(',') if row['images'] else []
        }
        for row in cursor.fetchall()
    ]
    conn.close()

    return render_template("home.html", user=user, short_name=user["short_name"], catalog_items=catalog_items)

@app.route("/my_orders")
def my_orders():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_catalog_db()
    cursor = conn.execute(
        "SELECT id, item_name, quantity, status, address1, address2, city, pincode, order_date FROM orders WHERE user_email = ?", 
        (user['email'],)
    )
    my_orders = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template("my_orders.html", user=user, short_name=user["short_name"], my_orders=my_orders)

@app.route("/orders")
def orders():
    user = get_user()
    if not user or user.get('role') != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for("home"))

    conn = get_catalog_db()
    cursor = conn.execute("SELECT * FROM orders")  # includes user_email
    orders = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template("orders.html", user=user, short_name=user["short_name"], orders=orders)

@app.route('/submit_order/<int:item_id>', methods=['POST'])
def submit_order(item_id):
    user = get_user()
    if not user:
        flash("Login required to submit an order", "error")
        return redirect(url_for("login"))

    name = request.form.get('name')
    contact = request.form.get('contact')
    email = request.form.get('email')
    address1 = request.form.get('address1')
    address2 = request.form.get('address2')
    city = request.form.get('city')
    pincode = request.form.get('pincode')

    conn = get_catalog_db()
    # First fetch item details from catalog
    item = conn.execute("SELECT name FROM catalog WHERE id = ?", (item_id,)).fetchone()
    if not item:
        flash("Item not found.", "error")
        conn.close()
        return redirect(url_for("home"))

    conn.execute('''
        INSERT INTO orders 
        (user_name, user_contact, user_email, item_id, item_name, quantity, status, address1, address2, city, pincode, order_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, DATE('now'))
    ''', (name, contact, email, item_id, item['name'], 1, 'pending', address1, address2, city, pincode))
    conn.commit()
    conn.close()

    flash('Order submitted successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/accept_order/<int:order_id>', methods=['POST'])
def accept_order(order_id):
    user = get_user()
    if not user or user['role'] != 'admin':
        flash("Unauthorized", "error")
        return redirect(url_for('home'))

    conn = get_catalog_db()
    conn.execute("UPDATE orders SET status = 'accepted' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    flash("Order accepted.", "success")
    return redirect(url_for('orders'))

@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    user = get_user()
    if not user:
        flash("Unauthorized", "error")
        return redirect(url_for("login"))

    conn = get_catalog_db()
    order = conn.execute("SELECT user_email FROM orders WHERE id = ?", (order_id,)).fetchone()
    if not order:
        flash("Order not found.", "error")
        conn.close()
        return redirect(url_for('home'))

    if user['email'] != order['user_email'] and user['role'] != 'admin':
        flash("Unauthorized to cancel this order.", "error")
        conn.close()
        return redirect(url_for('home'))

    conn.execute("UPDATE orders SET status = 'cancelled' WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    flash("Order cancelled.", "success")
    return redirect(url_for('orders') if user['role'] == 'admin' else url_for('my_orders'))

@app.route('/delete_order/<int:order_id>', methods=['POST'])
def delete_order(order_id):
    user = get_user()
    if not user or user['role'] != 'admin':
        flash("Unauthorized", "error")
        return redirect(url_for('home'))

    conn = get_catalog_db()
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()

    flash("Order deleted.", "success")
    return redirect(url_for('orders'))

@app.route("/sales")
def sales():
    user = get_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("sales.html", user=user, short_name=user.get("short_name"))

@app.route('/catalog', methods=['GET', 'POST'])
def catalog():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    short_name = user.get("short_name", "Guest")

    if request.method == 'POST':
        name = request.form['name']
        price = request.form['price']
        discount_price = request.form['discount_price']
        images = request.files.getlist('images')

        if not (1 <= len(images) <= 5):
            flash("Upload between 1 to 5 images.", "error")
            return redirect(url_for('catalog'))

        os.makedirs('static/catalog_uploads', exist_ok=True)
        saved_filenames = []

        for img in images:
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                img_path = os.path.join('static/catalog_uploads', filename)
                img.save(img_path)
                saved_filenames.append(filename)

        conn = get_catalog_db()
        conn.execute(
            "INSERT INTO catalog (name, price, discount_price, images) VALUES (?, ?, ?, ?)",
            (name, price, discount_price, ','.join(saved_filenames))
        )
        conn.commit()
        conn.close()

        flash("Catalog item added successfully!", "success")

    return render_template('catalog.html', user=user, short_name=short_name)

@app.route('/delete_catalog/<int:item_id>', methods=['POST'])
def delete_catalog(item_id):
    user = get_user()
    if not user or user.get("role") != "admin":
        flash("Unauthorized action.", "error")
        return redirect(url_for("home"))

    conn = get_catalog_db()
    cur = conn.cursor()

    images_row = cur.execute("SELECT images FROM catalog WHERE id = ?", (item_id,)).fetchone()
    if images_row:
        image_list = images_row[0].split(',')
        for img_filename in image_list:
            if img_filename:
                img_path = os.path.join(app.root_path, 'static/catalog_uploads', img_filename)
                if os.path.exists(img_path):
                    os.remove(img_path)

    cur.execute("DELETE FROM catalog WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

    flash("Catalog item deleted successfully.", "success")
    return redirect(url_for("home"))

@app.route("/inbox")
def inbox():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    conn = get_catalog_db()

    if user['role'] == 'admin':
        # Admin sees distinct users they've messaged or received messages from
        users_sent = conn.execute(
            "SELECT DISTINCT receiver_email FROM messages WHERE sender_email = ?", (user['email'],)
        ).fetchall()
        users_received = conn.execute(
            "SELECT DISTINCT sender_email FROM messages WHERE receiver_email = ?", (user['email'],)
        ).fetchall()

        user_emails = set([row['receiver_email'] for row in users_sent]) | set([row['sender_email'] for row in users_received])
        user_emails.discard(user['email'])

        # Connect to user.db for user names
        user_info_list = []
        user_db = sqlite3.connect('user.db')
        user_db.row_factory = sqlite3.Row

        for email in user_emails:
            user_info = user_db.execute(
                "SELECT first_name, last_name FROM users WHERE email = ?", (email,)
            ).fetchone()
            if user_info:
                # Check if any unread messages from this user
                unread = conn.execute(
                    "SELECT COUNT(*) as unread_count FROM messages WHERE sender_email = ? AND receiver_email = ? AND is_read = 0",
                    (email, user['email'])
                ).fetchone()['unread_count'] > 0

                user_info_list.append({
                    "name": f"{user_info['first_name']} {user_info['last_name']}",
                    "email": email,
                    "has_unread": unread
                })

        user_db.close()
        conn.close()
        return render_template("inbox.html", user=user, short_name=user.get("short_name"), user_list=user_info_list)

    else:
        # Regular user sees their chat
        messages = conn.execute(
            "SELECT * FROM messages WHERE sender_email = ? OR receiver_email = ? ORDER BY timestamp",
            (user['email'], user['email'])
        ).fetchall()
        conn.close()
        return render_template("chat.html", user=user, short_name=user.get("short_name"), messages=messages)

@app.route("/api/messages/<email>")
def get_messages(email):
    user = get_user()
    if not user:
        return jsonify([])

    conn = get_catalog_db()
    cursor = conn.cursor()

    # Fetch messages between current user and selected user
    messages = cursor.execute(
        "SELECT * FROM messages WHERE (sender_email = ? AND receiver_email = ?) OR (sender_email = ? AND receiver_email = ?) ORDER BY timestamp",
        (user['email'], email, email, user['email'])
    ).fetchall()

    # If admin is viewing, mark messages received from user as read
    if user['role'] == 'admin':
        cursor.execute(
            "UPDATE messages SET is_read = 1 WHERE sender_email = ? AND receiver_email = ? AND is_read = 0",
            (email, user['email'])
        )
        conn.commit()

    conn.close()
    return jsonify([dict(msg) for msg in messages])

@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages():
    user = get_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_catalog_db()
    admin_email = "admin@example.com"  # Your admin email

    if request.method == 'GET':
        messages = conn.execute(
            """
            SELECT * FROM messages 
            WHERE (sender_email = ? AND receiver_email = ?)
               OR (sender_email = ? AND receiver_email = ?)
            ORDER BY timestamp
            """,
            (user['email'], admin_email, admin_email, user['email'])
        ).fetchall()
        conn.close()
        return jsonify([dict(row) for row in messages])

    elif request.method == 'POST':
        data = request.get_json()
        message_text = data.get('message')
        receiver_email = data.get('receiver_email')
        if not message_text or not receiver_email:
            conn.close()
            return jsonify({"error": "Missing message or receiver"}), 400

        conn.execute(
            "INSERT INTO messages (sender_email, receiver_email, message, timestamp) VALUES (?, ?, ?, datetime('now'))",
            (user['email'], receiver_email, message_text)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True})

@app.route('/api/messages/clear', methods=['POST'])
def clear_chat():
    user = get_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_catalog_db()
    admin_email = "admin@example.com"

    # Delete messages between user and admin
    conn.execute(
        """
        DELETE FROM messages
        WHERE (sender_email = ? AND receiver_email = ?)
           OR (sender_email = ? AND receiver_email = ?)
        """,
        (user['email'], admin_email, admin_email, user['email'])
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True})

@app.route('/contact', methods=["GET", "POST"])
def contact():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        message_text = request.form.get("message", "").strip()
        if message_text:
            conn = get_catalog_db()
            conn.execute(
                "INSERT INTO messages (sender_email, receiver_email, message, timestamp) VALUES (?, ?, ?, datetime('now'))",
                (user['email'], "admin@example.com", message_text)
            )
            conn.commit()
            conn.close()
            flash("Message sent to admin.", "success")
        else:
            flash("Message cannot be empty.", "error")

    return render_template("contact.html", short_name=user["short_name"], user=user)

@app.route('/api/messages/<user_email>', methods=['GET', 'POST', 'DELETE'])
def messages(user_email):
    user = get_user()
    if not user:
        return {"error": "Unauthorized"}, 401

    conn = get_catalog_db()

    if request.method == 'GET':
        # Fetch messages between current user and user_email (admin or other)
        messages = conn.execute(
            """
            SELECT * FROM messages 
            WHERE (sender_email = ? AND receiver_email = ?) 
               OR (sender_email = ? AND receiver_email = ?)
            ORDER BY timestamp
            """,
            (user['email'], user_email, user_email, user['email'])
        ).fetchall()
        conn.close()
        # Convert rows to dict
        messages_list = [dict(row) for row in messages]
        return jsonify(messages_list)

    elif request.method == 'POST':
        data = request.get_json()
        message_text = data.get('message')
        if not message_text:
            conn.close()
            return {"error": "No message provided"}, 400
        
        conn.execute(
            "INSERT INTO messages (sender_email, receiver_email, message, timestamp) VALUES (?, ?, ?, datetime('now'))",
            (user['email'], user_email, message_text)
        )
        conn.commit()
        conn.close()
        return {"success": True}

    elif request.method == 'DELETE':
        # Delete all messages between current user and user_email
        conn.execute(
            """
            DELETE FROM messages 
            WHERE (sender_email = ? AND receiver_email = ?) 
               OR (sender_email = ? AND receiver_email = ?)
            """,
            (user['email'], user_email, user_email, user['email'])
        )
        conn.commit()
        conn.close()
        return {"success": True}

@app.route('/api/messages/<partner_email>', methods=['GET', 'POST'])
def api_messages_with_partner(partner_email):
    user = get_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_catalog_db()

    if request.method == 'GET':
        messages = conn.execute(
            """SELECT * FROM messages
            WHERE (sender_email = ? AND receiver_email = ?) OR (sender_email = ? AND receiver_email = ?)
            ORDER BY timestamp""",
            (user['email'], partner_email, partner_email, user['email'])
        ).fetchall()
        conn.close()
        return jsonify([dict(m) for m in messages])

    elif request.method == 'POST':
        data = request.json
        message_text = data.get('message', '').strip()
        if not message_text:
            return jsonify({"error": "Empty message"}), 400

        conn.execute(
            "INSERT INTO messages (sender_email, receiver_email, message, timestamp) VALUES (?, ?, ?, ?)",
            (user['email'], partner_email, message_text, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()

        return jsonify({"status": "sent"})

@app.route('/api/messages/clear', methods=['POST'])
def clear_messages():
    user = get_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_catalog_db()
    conn.execute(
        "DELETE FROM messages WHERE sender_email = ? OR receiver_email = ?", 
        (user['email'], user['email'])
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "cleared"})

# Admin views chat with a specific user
@app.route("/chat/<user_email>")
def chat_with_user(user_email):
    user = get_user()
    if not user or user['role'] != 'admin':
        flash("Unauthorized access.", "error")
        return redirect(url_for('login'))

    conn = get_catalog_db()
    messages = conn.execute(
        "SELECT * FROM messages WHERE (sender_email = ? AND receiver_email = ?) OR (sender_email = ? AND receiver_email = ?) ORDER BY timestamp",
        (user_email, user['email'], user['email'], user_email)
    ).fetchall()
    conn.close()

    return render_template("chat.html", user=user, messages=messages, chat_user=user_email)

@app.route("/settings")
def settings():
    user = get_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("settings.html", user=user, short_name=user.get("short_name"))

@app.route("/account", methods=["GET", "POST"])
def account_settings():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")

        conn = sqlite3.connect("user.db")
        cur = conn.cursor()

        if 'remove_image' in request.form:
            cur.execute("UPDATE users SET profile_image = NULL WHERE email = ?", (user["email"],))
        elif 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute("UPDATE users SET profile_image = ? WHERE email = ?", (filename, user["email"]))

        cur.execute(
            "UPDATE users SET first_name = ?, last_name = ? WHERE email = ?", 
            (first_name, last_name, user["email"])
        )
        conn.commit()
        conn.close()

        flash("Account updated successfully.", "success")
        user = get_user()

    return render_template("account.html", user=user)

@app.route("/change-password", methods=["POST"])
def change_password():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    old_pw = request.form.get("old_password")
    new_pw = request.form.get("new_password")
    confirm_pw = request.form.get("confirm_password")

    if new_pw != confirm_pw:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("account_settings"))

    conn = sqlite3.connect("user.db")
    cur = conn.cursor()
    row = cur.execute("SELECT password FROM users WHERE email = ?", (user["email"],)).fetchone()

    if row and check_password_hash(row[0], old_pw):
        cur.execute("UPDATE users SET password = ? WHERE email = ?", (generate_password_hash(new_pw), user["email"]))
        conn.commit()
        flash("Password updated successfully.", "success")
    else:
        flash("Current password is incorrect.", "error")
    conn.close()

    return redirect(url_for("account_settings"))

@app.route("/delete-account", methods=["POST"])
def delete_account():
    user = get_user()
    if not user:
        return redirect(url_for("login"))

    email = user["email"]
    if email == "admin@example.com":
        return redirect(url_for("account_settings", admin_delete_blocked=1))

    conn = sqlite3.connect("user.db")
    conn.execute("DELETE FROM users WHERE email = ?", (email,))
    conn.commit()
    conn.close()

    session.pop("user", None)
    flash("Your account has been deleted.", "success")
    return redirect(url_for("register"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        conn = sqlite3.connect('user.db')
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user[5], password):
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))

        db_role = user[7] if len(user) > 7 else "user"
        if role == "admin" and db_role != "admin":
            flash("You are not authorized to log in as Admin.", "error")
            return redirect(url_for("login"))

        session["user"] = email
        return redirect(url_for("home"))

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        mobile = request.form.get("mobile")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)

        conn = sqlite3.connect('user.db')
        try:
            conn.execute(
                "INSERT INTO users (first_name, last_name, mobile, email, password, role) VALUES (?, ?, ?, ?, ?, ?)",
                (first_name, last_name, mobile, email, hashed_pw, 'user')
            )
            conn.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
