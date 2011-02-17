from flask import Flask
from flaskext.sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config.from_envvar('CIRCLES_SETTINGS')
db = SQLAlchemy(app)

import circles.main
