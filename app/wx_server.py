import time
import json
import math
from lxml import etree
from app.jwgl_client import Login
from app.jwgl_client import Data
from app.models import *
from app.config import start_time


class MsgReceive(object):
    def __init__(self, xml_msg):
        self.msg = etree.fromstring(xml_msg)
        self.msg_type = self.msg.find('MsgType').text
        self.from_user = self.msg.find('FromUserName').text
        self.to_user = self.msg.find('ToUserName').text

    def deal(self):
        if self.msg_type == 'text':
            if '@@@' in self.msg.find('Content').text:
                u = self.msg.find('Content').text.split('@@@')[0]
                p = self.msg.find('Content').text.split('@@@')[1]
                print(p + u)
                login = Login(u, p)
                cookies = login.get_cookies()
                if cookies:
                    data = Data(cookies)
                    grades = data.get_grades(u).encode('utf-8')
                    exam = data.get_exam(u).encode('utf-8')
                    if not exam:
                        exam = ''
                    insert_user(self.from_user, u, p, exam, grades)
                    print('++++++++++' + 'insert')
                    for week in range(1, 18):
                        course = data.get_lessons_by_week(week).encode('utf-8')
                        insert_course(u, week, course)
                    return self._replay('text', '绑定成功！')
                else:
                    return self._replay('text', '用户名或密码错误！')
            else:
                return self._replay('text', 'This is a test msg for TEXT!')
        elif self.msg_type == 'event':
            event_key = self.msg.find('EventKey').text
            if event_key in ['course', 'exam', 'grades']:
                user = select_user(self.from_user)
                if user:
                    msg = ''
                    if event_key == 'grades':
                        grades = json.loads(user.grades)
                        for grade in grades:
                            msg += grade[0] + ' ' + grade[1] + ' ' + grade[2] + '\n'

                    elif event_key == 'exam':
                        exams = json.loads(user.exam)
                        for exam in exams:
                            msg += exam[0] + ' ' + exam[1] + ' ' + exam[2] + ' ' + exam[3] + '\n'

                    elif event_key == 'course':
                        # 通过时间戳获得当前时间是第几周，星期几，这需要开学时间
                        t = time.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                        start_timestamp = int(time.mktime(t))
                        week = math.ceil((time.time() - start_timestamp) / (7 * 24 * 60 * 60))
                        day = math.ceil(((time.time() - start_timestamp) % (7 * 24 * 60 * 60)) / (24 * 60 * 60))
                        course = select_course(user.username, week)
                        course = json.loads(course.course)
                        msg += 'Week：' + str(week) + '     Day：' + str(day) + '\n'
                        for i in range(12):
                            a_lesson = course[i][day]
                            if a_lesson != 'null':
                                msg += '第' + str(i + 1) + '节： ' + course[i][day] + '\n'
                    return self._replay('text', msg)
                else:
                    return self._replay('text',
                                        'Not bind your JWGL account\nPlease send username@@@password to bind\neg. 16020032029@@@123456')

    def _replay(self, msg_type, content):
        msg_reply = MsgReply(self.from_user, self.to_user, msg_type, content)
        return msg_reply.render()


class MsgReply(object):
    """回复消息"""
    TEMPLATE_TEXT = u"""
	<xml>
    <ToUserName><![CDATA[{target}]]></ToUserName>
    <FromUserName><![CDATA[{source}]]></FromUserName>
    <CreateTime>{time}</CreateTime>
    <MsgType><![CDATA[{msg_type}]]></MsgType>
    <Content><![CDATA[{content}]]></Content>
    </xml>
	"""

    def __init__(self, target, source, msg_type, content):
        self.target = target
        self.source = source
        self.msg_type = msg_type
        self.content = content
        self.time = int(time.time())

    def text_render(self):
        return MsgReply.TEMPLATE_TEXT.format(target=self.target, source=self.source,
                                             time=self.time, msg_type=self.msg_type, content=self.content)

    def event_render(self):
        return MsgReply.TEMPLATE_TEXT.format(target=self.target, source=self.source,
                                             time=self.time, msg_type=self.msg_type, content=self.content)

    def render(self):
        if self.msg_type == 'text':
            return self.text_render()
        elif self.msg_type == 'event':
            return self.event_render
