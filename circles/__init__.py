from flask import Flask
from flaskext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'seeeecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://nick@localhost/circles'
db = SQLAlchemy(app)

import circles.main
