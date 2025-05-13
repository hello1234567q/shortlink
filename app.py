from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
@app.after_request
def inject_ads(response):
    if response.content_type.startswith('text/html'):
        ad_code = '''
        <div style="position:fixed;bottom:10px;right:10px;z-index:9999;">
          <!-- Google Ads script -->
          <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js"></script>
          <ins class="adsbygoogle"
              style="display:block"
              data-ad-client="ca-pub-XXXXXXXXXXXXXXXX"
              data-ad-slot="YYYYYYYYYY"
              data-ad-format="auto"
              data-full-width-responsive="true"></ins>
          <script>
              (adsbygoogle = window.adsbygoogle || []).push({});
          </script>
        </div>
        </body>
        '''
        html = response.get_data(as_text=True)
        if "</body>" in html:
            html = html.replace("</body>", ad_code)
            response.set_data(html)
    return response

# MongoDB setup
client = MongoClient(os.getenv("MONGO_URI"))
db = client["shortlink_app"]
users_collection = db["users"]
links_collection = db["links"]

# SQLite setup for expiration
sqlite_conn = sqlite3.connect("expiring_links.db", check_same_thread=False)
sqlite_cursor = sqlite_conn.cursor()
sqlite_cursor.execute('''CREATE TABLE IF NOT EXISTS expiring_links (
    alias TEXT PRIMARY KEY,
    expire_at TEXT
)''')
sqlite_conn.commit()


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]
        email = request.form["email"]
        accept = request.form.get("agree")

        if not accept:
            flash("You must accept the privacy policy.", "danger")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))
        if users_collection.find_one({"username": username}):
            flash("Username already exists.", "danger")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            "username": username,
            "password": hashed_password,
            "email": email
        })
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = users_collection.find_one({"username": username})
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    user = users_collection.find_one({"username": session["user"]})
    user_links = list(links_collection.find({"user_id": user["_id"]}))

    # Lấy ngày hết hạn từ SQLite
    expire_data = {}
    for link in user_links:
        sqlite_cursor.execute("SELECT expire_at FROM expiring_links WHERE alias = ?", (link["alias"],))
        row = sqlite_cursor.fetchone()
        expire_data[link["alias"]] = row[0] if row else None

    return render_template("dashboard.html", links=user_links, expire_data=expire_data)


@app.route("/create", methods=["GET", "POST"])
def create():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        alias = request.form["alias"].strip()
        url = request.form["url"]
        expire = request.form.get("expire")
        password = request.form.get("password") or None
        is_dangerous = True if request.form.get("dangerous") else False

        if links_collection.find_one({"alias": alias}):
            flash("Alias already exists.", "danger")
            return redirect(url_for("create"))

        user = users_collection.find_one({"username": session["user"]})

        data = {
            "alias": alias,
            "original_url": url,
            "user_id": user["_id"],
            "is_dangerous": is_dangerous,
        }

        if password:
            data["password"] = generate_password_hash(password)

        links_collection.insert_one(data)

        if expire:
            try:
                expire_date = datetime.strptime(expire, "%Y-%m-%d")
                sqlite_cursor.execute(
                    "INSERT OR REPLACE INTO expiring_links (alias, expire_at) VALUES (?, ?)",
                    (alias, expire_date.isoformat()))
                sqlite_conn.commit()
            except ValueError:
                flash("Invalid expiration date.", "danger")
                return redirect(url_for("create"))

        flash("Short link created.", "success")
        return redirect(url_for("dashboard"))

    return render_template("create.html")


@app.route("/delete/<alias>")
def delete_link(alias):
    if "user" not in session:
        return redirect(url_for("login"))

    user = users_collection.find_one({"username": session["user"]})
    links_collection.delete_one({"alias": alias, "user_id": user["_id"]})

    sqlite_cursor.execute("DELETE FROM expiring_links WHERE alias = ?", (alias,))
    sqlite_conn.commit()

    flash("Link deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/<alias>", methods=["GET", "POST"])
def redirect_link(alias):
    link = links_collection.find_one({"alias": alias})
    if not link:
        return "Link not found", 404

    # Check expiration
    sqlite_cursor.execute("SELECT expire_at FROM expiring_links WHERE alias = ?", (alias,))
    row = sqlite_cursor.fetchone()
    if row and datetime.fromisoformat(row[0]) < datetime.now():
        return "Link expired", 410

    # Password protection
    if "authenticated_links" not in session:
        session["authenticated_links"] = []

    if link.get("password") and alias not in session["authenticated_links"]:
        if request.method == "POST":
            entered_password = request.form["password"]
            if check_password_hash(link["password"], entered_password):
                session["authenticated_links"].append(alias)
            else:
                return render_template("password_prompt.html", error="Incorrect password")
        else:
            return render_template("password_prompt.html", error=None)

    # Warning page for dangerous links
    if link.get("is_dangerous"):
        return render_template("warning.html", url=link["original_url"])

    return redirect(link["original_url"])


if __name__ == "__main__":
    app.run(debug=True)