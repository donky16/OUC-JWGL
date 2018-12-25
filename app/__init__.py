# -*- coding:utf-8 -*-
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import config

app = Flask(__name__)
app.config.from_object(config)
db = SQLAlchemy(app, use_native_unicode="utf8")

from app.models import User
from app.models import Course
