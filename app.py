from flask import Flask
from datetime import timedelta
from globalVariable import *

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = timedelta(days=7)

