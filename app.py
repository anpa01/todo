import os
import datetime
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required
from cs50 import SQL

app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///todo.db")

@app.route("/", methods=['POST', 'GET'])
@login_required
def index():
    if request.method == "POST":
        task = request.form.get("task")
        if not request.form.get("task"):
            return redirect("/")
        tasks = []
        finished = []
        username = db.execute("SELECT username FROM users WHERE user_id = :user",
                            user=session['user_id'])[0]['username']
        db.execute("INSERT INTO tasks (user_id, task1, username) VALUES (:user, :task, :username)",
                    user=session["user_id"], task=task, username=username)
        rows = db.execute("SELECT * FROM tasks WHERE user_id = :user",
                        user=session["user_id"])
        for row in rows:
            tasks.append((list((row['task1'], row['id']))))
        rows2 = db.execute("SELECT * FROM finished WHERE user_id = :user",
                            user=session['user_id'])
        for row in rows2:
            finished.append((list((row['task'], row['date']))))
        return render_template("index.html", tasks = tasks, finished = finished)
    else:
        tasks = []
        finished = []
        rows = db.execute("SELECT * FROM tasks WHERE user_id = :user",
                        user=session["user_id"])
        rows2 = db.execute("SELECT * FROM finished WHERE user_id = :user",
                            user=session['user_id'])
        for row in rows2:
            finished.append((list((row['task'], row['date']))))
        for row in rows:
            tasks.append((list((row['task1'], row['id']))))
        return render_template("index.html", tasks = tasks, finished = finished)



@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        x = True
        y = True
        while x:
            if not request.form.get("username"):
                flash("Must put in username.")
            else:
                x = False
        while y:
            if not request.form.get("password"):
                flash("Must put in password")
            else:
                y = False
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Login is incorrect. Please try again.")
            return redirect("/login")
        blocked = db.execute("SELECT * FROM users WHERE username = :username",
                                username=request.form.get("username"))[0]['blocked']
        if request.form.get('username') == 'admin':
            session["user_id"] = rows[0]["user_id"]
            return redirect("/admin")
        elif blocked == 1:
            flash("This account has been blocked")
            return redirect("/login")
        session["user_id"] = rows[0]["user_id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/admin")
@login_required
def admin():
    infos = []
    users = []
    rows = db.execute("SELECT * FROM users")
    for row in rows:
        if row['username'] != 'admin':
            users.append(row['username'])
    for user in users:
        counter1 = 0
        rows1 = db.execute("SELECT * FROM tasks WHERE username = :user",
                        user=user)
        for row in rows1:
            counter1 += 1
        counter2 = 0
        rows2 = db.execute("SELECT * FROM finished WHERE username = :user",
                        user=user)
        for row2 in rows2:
            counter2 += 1
        blocked = db.execute("SELECT * FROM users WHERE username = :user",
                            user=user)[0]['blocked']
        infos.append((list((user, counter1 , counter2, blocked))))
    return render_template("admin.html", infos = infos)


@app.route("/block/<username>")
@login_required
def block(username):
    blocked = 1
    db.execute("UPDATE users SET blocked = :blocked WHERE username = :username",
                blocked=blocked, username=username)
    return redirect("/admin")


@app.route("/unblock/<username>")
@login_required
def unblock(username):
    blocked = 0
    db.execute("UPDATE users SET blocked = :blocked WHERE username = :username",
                blocked=blocked, username=username)
    return redirect("/admin")




@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/login")
    flash("Successfully logged out!")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        name = request.form.get("username")
        password1 = request.form.get("password")
        password2 = request.form.get("password2")
    if not name:
        flash("Must provide username.")
        return redirect("/register")
    elif not password1:
        flash("Must provide password.")
        return redirect("/register")
    elif not password2:
        flash("Must provide confirmation.")
        return redirect("/register")
    elif password1 != password2:
        flash("Passwords don't match.")
        return redirect("/register")
    elif db.execute("SELECT * FROM users WHERE username = :name",
            name=name):
        flash("Username has been taken.")
        return redirect("/register")
    else:
        db.execute("INSERT INTO users(username, hash) VALUES (:name, :hash)",
            name=name, hash=generate_password_hash(request.form.get("password")))
        return redirect("/login")

@app.route("/remove/<task_id>")
@login_required
def remove(task_id):
    db.execute("DELETE FROM tasks WHERE user_id = :user AND id = :task_id",
                    user=session["user_id"], task_id=task_id)
    return redirect("/")

@app.route("/finish/<task_id>")
@login_required
def finish(task_id):
    date = datetime.datetime.now()
    username = db.execute("SELECT username FROM users WHERE user_id = :user",
                            user=session['user_id'])[0]['username']
    task = db.execute("SELECT task1 FROM tasks WHERE user_id = :user AND id = :task_id",
                        user=session["user_id"], task_id=task_id)[0]['task1']
    db.execute("DELETE FROM tasks WHERE user_id = :user AND id = :task_id",
                user=session["user_id"], task_id=task_id)
    db.execute("INSERT INTO finished(user_id, task, date, username) VALUES (:user, :task, :date, :username)",
                user=session["user_id"], task=task, date=date, username=username)
    return redirect("/")