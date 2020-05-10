from flask import Flask
from datetime import timedelta
from globalVariable import *

def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    app.permanent_session_lifetime = timedelta(days=7)
    return app
