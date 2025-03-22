"""
JWT: JSON Web Tokens

This python code implements an authentication wrapper using JWT

Questions: 
1. Identify potential security issues in JWT and database interactions.
2. Describe all attack scenarios in as much detail as possible using the security issues reported.
3. Provide fixes for all the identified issues.

How: 
Research on common SQL and JWT issues and bypasses.
"""

from flask import Flask, request, make_response, escape
import jwt
import pickle
import sqlite3
import logging
import datetime
import os
from utils.db_utils import DatabaseUtils
from utils.file_storage import FileStorage
from werkzeug.utils import secure_filename

app = Flask(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")

logging.basicConfig(level=logging.INFO)
db = DatabaseUtils()
fs = FileStorage()

def _init_app():
    db.update_data("DROP TABLE IF EXISTS users;")
    db.update_data('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            password TEXT NOT NULL,
                            privilege INTEGER
                        );''')
    db.update_data("INSERT INTO users (username, password, privilege) VALUES ('user1', 'password1', 0)")
    db.update_data("INSERT INTO users (username, password, privilege) VALUES ('admin1', 'adminpassword1', 1)")

def _check_login():
    auth_token = request.cookies.get('token', None)
    if not auth_token:
        raise "Missing token cookie"
    try:
        # Decode JWT token
        token = auth_token[len(auth_token)//2:] + auth_token[:len(auth_token)//2]
        data = jwt.decode(pickle.loads(bytes.fromhex(token)), SECRET_KEY, algorithms=["HS256"])
    except jwt.DecodeError:
        raise "Token is invalid"
    return data

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    rows = db.fetch_data("SELECT * FROM users where username=? AND password=?", (username, password))

    if len(rows) != 1:
        return "Invalid credentials"
    
    expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    token = jwt.encode({"username": username, "exp": expiry, "admin": rows[0][-1] == 1}, SECRET_KEY, algorithm="HS256")
    obfuscate1 = pickle.dumps(token.encode())
    obfuscate2 = obfuscate1.hex()
    obfuscate3 = obfuscate2[len(obfuscate2)//2:] + obfuscate2[:len(obfuscate2)//2]
    # Everyone knows how to read JWT tokens these days. The team decided to obfuscate it as a pickle and
    # some fancy tricks so nobody can tell we're using JWT and can't exploit us using common JWT exploits :D
    # Devs knowing some security sure is useful! :P

    res = make_response()
    res.set_cookie("token", value=obfuscate3, httponly=True, samesite='Lax')

    return res

@app.route("/file", methods=["GET", "POST", "DELETE"])
def store_file():
    """
    Only admins can upload/delete files.
    All users can read files.
    """
    try:
        data = _check_login()
    except:
        return "Not logged in"

    is_admin = data.get("admin", False)

    if request.method == 'GET':
        filename = secure_filename(request.args.get('filename'))
        return fs.get(filename)
    elif request.method == 'POST':
        if not is_admin: return "Need admin access"
        uploaded_files = request.files
        logging.error(uploaded_files)
        for f in uploaded_files:
            fs.store(secure_filename(uploaded_files[f].name), uploaded_files[f].read())
            logging.info(f'Uploaded filename: {uploaded_files[f].name}')
        return "Files uploaded successfully"
    elif request.method == 'DELETE':
        if not is_admin: return "Need admin access"
        filename = secure_filename(request.args.get('filename'))
        fs.delete(filename)
        return f"{escape(filename)} deleted successfully"
    else:
        return "Method not implemented"

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

if __name__ == "__main__":
    _init_app()
    app.run(host='0.0.0.0', debug=True, port=9090)
