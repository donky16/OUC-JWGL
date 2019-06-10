# -*- coding:utf-8 -*-

from app import db
from app.jwgl_client import Data, Login


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    openid = db.Column(db.String(50), unique=True)  # 用户的唯一标志
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(32), nullable=False)
    exam = db.Column(db.String(1000), nullable=True)
    grades = db.Column(db.String(10000), nullable=True)


def insert_user(openid, username, password, exam, grades):
    user = User(openid=openid, username=username, password=password, exam=exam, grades=grades)
    db.session.add(user)
    db.session.commit()
    print('[+] insert user: ' + username + '@' + 'password')


def select_user(openid):
    user = User.query.filter_by(openid=openid).first()
    if user:
        return user
    return False


class Course(db.Model):
    __tablename__ = 'course'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    week = db.Column(db.Integer, nullable=False)
    course = db.Column(db.String(3000), nullable=False)

    def __repr__(self):
        return '<User %r>' % self.username


def insert_course(username, week, course):
    course = Course(username=username, week=week, course=course)
    db.session.add(course)
    db.session.commit()
    print('[+] insert course: ' + username + '@' + str(week))


def select_course(username, week):
    course = Course.query.filter_by(username=username, week=week).first()
    return course


def insert_data(u, p, openid, cookies):
    if cookies:
        data = Data(cookies)
        grades = data.get_grades(u).encode('utf-8')
        exam = data.get_exam(u).encode('utf-8')
        if not exam:
            exam = ''
        insert_user(openid, u, p, exam, grades)
        for week in range(1, 18):
            course = data.get_lessons_by_week(week).encode('utf-8')
            insert_course(u, week, course)
