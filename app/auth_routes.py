from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
from .database import get_db
from .auth import ensure_admin, audit

auth_bp=Blueprint("auth",__name__)


@auth_bp.get("/login")
def login():
    ensure_admin()
    if session.get("user_id"):
        return redirect(url_for("web.dashboard"))
    return render_template("login.html")


@auth_bp.post("/login")
def login_post():
    ensure_admin()
    username=request.form.get("username","").strip()
    password=request.form.get("password","")
    conn=get_db()
    user=conn.execute(
        "SELECT id,username,password_hash,role,active FROM users WHERE username=?",
        (username,)
    ).fetchone()
    conn.close()

    if not user or not user["active"] or not check_password_hash(user["password_hash"],password):
        audit(username or "unknown", "LOGIN_FAILED")
        return render_template("login.html",error="Invalid username or password"),401

    session.clear()
    session["user_id"]=user["id"]
    session["username"]=user["username"]
    audit(user["username"],"LOGIN")
    return redirect(request.args.get("next") or url_for("web.dashboard"))


@auth_bp.post("/logout")
def logout():
    username=session.get("username","unknown")
    user_id=session.get("user_id")
    if user_id:
        conn=get_db()
        row=conn.execute("SELECT username FROM users WHERE id=?",(user_id,)).fetchone()
        conn.close()
        if row: username=row["username"]
    audit(username,"LOGOUT")
    session.clear()
    return redirect(url_for("auth.login"))
