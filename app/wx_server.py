import time
import json
import math
import threading
import hashlib
import requests
from app.utils import weather_api
from lxml import etree
from app.models import *
from app.config import start_time


class MsgReceive(object):
    def __init__(self, xml_msg):
        self.msg_receive = etree.fromstring(xml_msg)
        self.msg_type = self.msg_receive.find('MsgType').text
        self.from_user = self.msg_receive.find('FromUserName').text
        self.to_user = self.msg_receive.find('ToUserName').text

    def deal(self):
        if self.msg_type == 'text':
            content = self.msg_receive.find('Content').text
            if '@@@' in content:
                # 绑定功能
                u = content.split('@@@')[0]
                p = content.split('@@@')[1]
                if len(u) == 11:
                    md5_p = hashlib.md5(p.encode('utf-8')).hexdigest()
                    login = Login(u, md5_p)
                    cookies = login.get_cookies()
                    if cookies:
                        # 多线程获取数据并插入数据库
                        insert_thread = threading.Thread(target=insert_data, args=(u, md5_p, self.from_user, cookies))
                        insert_thread.start()
                        return self._replay('text', '绑定成功！')
                    else:
                        return self._replay('text', '用户名或密码错误！')
                else:
                    return self._replay('text', '用户名不符合学号格式！')
            elif 'course:' == content[0:7]:
                # 我的课表功能
                user = select_user(self.from_user)
                if user:
                    msg = ''
                    data = content[7:]
                    if ' ' in data:
                        # 查询具体天的课表
                        week = int(data.split(' ')[0])
                        day = int(data.split(' ')[1])
                        if (0 < week <= 17) and (7 >= day > 0):
                            msg += self.get_course_info(user, week, day)
                        else:
                            msg += '回复week和day不再实际范围内(0<week<18 0<day<8)'
                    else:
                        week = int(data)
                        if 0 < week <= 17:
                            # 查询一周课表
                            for day in range(1, 8):
                                msg += self.get_course_info(user, week, day)
                        else:
                            msg += '回复week不再实际范围内(0<week<18)'
                    return self._replay('text', msg)
                else:
                    return self._replay('text',
                                        'Not bind your JWGL account\nPlease send username@@@password to bind\neg. 16020032029@@@123456')
            elif content[0:5] == 'talk:':
                advice = self.msg_receive.find('CreateTime').text + ': '
                advice += content[5:] + '\n'
                with open('./app/static/advice.txt', 'a') as f:
                    f.write(advice)
                return self._replay('text', '我们已经收到您宝贵的建议，非常感谢！')
            else:
                return self._replay('text', '回复消息，没有对应功能，请检查后按格式回复数据！')
        elif self.msg_type == 'event':
            event_key = self.msg_receive.find('EventKey').text
            if event_key in ['course', 'exam', 'grades', 'today-course']:
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

                    elif event_key == 'today-course':
                        # 通过时间戳获得当前时间是第几周，星期几，这需要开学时间
                        t = time.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                        start_timestamp = int(time.mktime(t))
                        week = math.ceil((time.time() - start_timestamp) / (7 * 24 * 60 * 60))
                        day = math.ceil(((time.time() - start_timestamp) % (7 * 24 * 60 * 60)) / (24 * 60 * 60))
                        # msg += 'Week：' + str(week) + '     Day：' + str(day) + '\n'
                        msg += self.get_course_info(user, week, day)
                        msg += 'ps: 查询其他课表，请点击我的课表\n'
                    elif event_key == 'course':
                        msg += '请回复course:week day查询具体时间的课表\neg. course:2 3 第二周星期三课表\neg. course:2 第二周课表'
                    return self._replay('text', msg)

                else:
                    return self._replay('text',
                                        '用户未绑定，请回复username@@@password来绑定账号\neg. 16020032029@@@123456')
            elif event_key == 'weather':
                msg = weather_api.get_weather('青岛')
                return self._replay('text', msg)
            elif event_key == 'activity':
                with open('./app/static/recent_activity.txt', encoding='utf-8') as f:
                    activity = f.read()
                f.close()
                return self._replay('text', activity)
            elif event_key == 'photo':
                return self._replay('text', '正在保存图片...')
            elif event_key == 'nothing':
                return self._replay('text', '更多功能，敬请期待！')
            elif event_key == 'talk':
                return self._replay('text', '感谢您能为我们提出意见或建议，回复talk:建议即可\neg. talk:能不能加个查询选课币的功能？')
            elif event_key == 'us':
                return self._replay('text',
                                    '开发者：donky16 QQ:973505626\n其他成员：\n  太阳黑了 QQ:1683840133\n  努力的小四  QQ:793340156')
        elif self.msg_type == 'image':
            pic_url = self.msg_receive.find('PicUrl').text
            r = requests.get(pic_url)
            img_name = './app/static/img/' + self.from_user + self.msg_receive.find('CreateTime').text + '.png'
            with open(img_name, 'wb') as f:
                f.write(r.content)
            msg = '保存图片成功，点击链接查看图片' + pic_url
            return self._replay('text', msg)

    def get_course_info(self, user, week, day):
        msg = ''

        # print('[+] week' + week)
        course = select_course(user.username, week)
        course = json.loads(course.course)
        msg += 'Week：' + str(week) + '     Day：' + str(day) + '\n'
        is_null = True
        for i in range(12):
            a_lesson = course[i][day - 1]
            if a_lesson != 'null':
                is_null = False
                msg += '第' + str(i + 1) + '节： ' + a_lesson + '\n'
        if is_null:
            msg += '很开心，今天没课(:\n'
        return msg

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
            return self.event_render()
