from datetime import datetime
from enum import Enum, auto
from functools import wraps
from itertools import count
from os import environ as env
from typing import Generator
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, session, url_for, jsonify, request

comments_list = ['<script>alert("XSS attack has happened")</script>']
break_or_make_var = None
xss_toggle = None
auth_users = ['auth0|6356ed1d5615e6a1bdb56435', 'auth0|6356ee6ae584359a2df8303a', 'auth0|6356ed948d3ef662e0286c6d']

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)


def authenticate() -> bool:
    if 'user' not in session:
        return False

    user_id = session['user']['userinfo']['sub']

    return user_id in auth_users


@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get('user'),
        comments=comments_list,
        xss_toggle=xss_toggle,
        is_auth=authenticate()
    )


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


@app.post('/add_comment')
def add_comment():
    comments_list.append(request.form.get('comment'))
    return redirect('/')


@app.post('/toggle_xss')
def toggle_xss():
    global xss_toggle
    xss_toggle = request.form.get('is_safe')
    return redirect('/')


@app.post('/break_or_make')
def break_or_make():
    global break_or_make_var
    break_or_make_var = request.form.get('is_safe')

    return redirect('/')


@app.get('/delete_comments')
def delete_comments():
    if break_or_make_var:
        if not authenticate():
            return 'Unauthorized'

    while comments_list:
        comments_list.pop()

    return redirect('/')


if __name__ == '__main__':
    app.run()
