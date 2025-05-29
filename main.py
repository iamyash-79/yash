from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user():
    conn = sqlite3.connect('user.db')
    row = conn.execute("SELECT first_name, last_name, email, profile_image, role FROM users WHERE email = ?", (session["user"],)).fetchone()
    conn.close()
    if row and len(row) == 5:
        return {
            "name": f"{row[0]} {row[1]}",
            "first_name": row[0],
            "last_name": row[1],
            "email": row[2],
            "profile_image": row[3],
            "role": row[4],
            "short_name": row[0]
        }
    else:
        return {}

@app.route("/")
@app.route("/home")
def home():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("home.html", user=user, short_name=user.get("short_name"))

@app.route("/My_Orders")
def My_Orders():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("My_Orders.html", user=user, short_name=user.get("short_name"))

@app.route("/Orders")
def Orders():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("Orders.html", user=user, short_name=user.get("short_name"))

@app.route("/sales")
def sales():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("sales.html", user=user, short_name=user.get("short_name"))

@app.route("/catalog")
def catalog():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("catalog.html", user=user, short_name=user.get("short_name"))

@app.route("/inbox")
def inbox():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("inbox.html", user=user, short_name=user.get("short_name"))

@app.route("/Contact")
def Contact():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("Contact.html", user=user, short_name=user.get("short_name"))

@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))
    user = get_user()
    return render_template("settings.html", user=user, short_name=user.get("short_name"))

@app.route("/account", methods=["GET", "POST"])
def account_settings():
    if not session.get("user"):
        return redirect(url_for("login"))

    conn = sqlite3.connect("user.db")
    cur = conn.cursor()

    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")

        if 'remove_image' in request.form:
            cur.execute("UPDATE users SET profile_image = NULL WHERE email = ?", (session["user"],))
        elif 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cur.execute("UPDATE users SET profile_image = ? WHERE email = ?", (filename, session["user"]))

        cur.execute("UPDATE users SET first_name = ?, last_name = ? WHERE email = ?", (first_name, last_name, session["user"]))
        conn.commit()

    # Re-fetch updated user info
    user = cur.execute("SELECT first_name, last_name, email, profile_image FROM users WHERE email = ?", (session["user"],)).fetchone()
    conn.close()
    return render_template("account.html", user=user)

@app.route("/change-password", methods=["POST"])
def change_password():
    if "user" not in session:
        return redirect(url_for("login"))

    old_pw = request.form["old_password"]
    new_pw = request.form["new_password"]
    confirm_pw = request.form["confirm_password"]

    if new_pw != confirm_pw:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("account_settings"))

    conn = sqlite3.connect("user.db")
    row = conn.execute("SELECT password FROM users WHERE email = ?", (session["user"],)).fetchone()

    if row and check_password_hash(row[0], old_pw):
        conn.execute("UPDATE users SET password = ? WHERE email = ?", (generate_password_hash(new_pw), session["user"]))
        conn.commit()
        flash("Password updated successfully.", "success")
    else:
        flash("Current password is incorrect.", "error")
    conn.close()
    return redirect(url_for("account_settings"))

@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "user" not in session:
        return redirect(url_for("login"))

    email = session.get("user")
    if email == "admin@example.co":
        # Pass error through query string
        return redirect(url_for("account_settings", admin_delete_blocked=1))

    session.pop("user")
    conn = sqlite3.connect("user.db")
    conn.execute("DELETE FROM users WHERE email = ?", (email,))
    conn.commit()
    conn.close()
    flash("Your account has been deleted.", "success")
    return redirect(url_for("register"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        role = request.form.get("role")  # new: from the radio buttons

        conn = sqlite3.connect('user.db')
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user[5], password):
            flash("Invalid email or password", "error")
            return redirect(url_for("login"))

        db_role = user[7] if len(user) > 7 else "user"  # fallback

        if role == "admin" and db_role != "admin":
            flash("You are not authorized to log in as Admin.", "error")
            return redirect(url_for("login"))

        session["user"] = email
        return redirect(url_for("home"))
    
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        mobile = request.form["mobile"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        conn = sqlite3.connect('user.db')
        try:
            conn.execute(
    "INSERT INTO users (first_name, last_name, mobile, email, password, role) VALUES (?, ?, ?, ?, ?, ?)",
    (first_name, last_name, mobile, email, hashed_pw, 'user'))
            conn.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already registered.", "error")
        conn.close()
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
