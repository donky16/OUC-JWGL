# -*- coding:utf-8 -*-
from bs4 import BeautifulSoup
import json
import requests
import base64
import hashlib
import string
from PIL import Image
import pytesseract
import os
import time

from app import des_enc


class Login:
    def __init__(self, username, password, validate_code_len=4):
        self.valicode_code_num = 0  # 记录失败的验证码数量
        self.validate_code_len = validate_code_len  # 验证码的长度
        self.username = username
        self.password = password

        self.index_url = 'http://jwgl.ouc.edu.cn/cas/login.action'
        self.login_url = 'http://jwgl.ouc.edu.cn/cas/logon.action'
        self.headers = {
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'''
        }
        self.session = requests.Session()
        self.session.get(self.index_url, headers=self.headers)

    def _image_to_text(self, filename):
        '''
        使用pytesseract模块
        1000次验证码数据测试正确率
            1. 直接使用pyteeseract 29.24%
            2. 将图片转为灰度图像    30.46%
            3. 灰度图像，再进行二值化，阈值为100 15.78%
        '''
        if os.name == 'nt':
            pytesseract.pytesseract.tesseract_cmd = "C:\\Program Files (x86)\\Tesseract-OCR\\tesseract.exe"
        im = Image.open(filename)
        im = im.convert("L")
        #
        # threshold = 100
        # table = []
        # for i in range(256):
        #     if i < threshold:
        #         table.append(0)
        #     else:
        #         table.append(1)
        # im = im.point(table, "1")

        try:
            text = pytesseract.image_to_string(im)
            return text
        except:
            pass
        return ''

    def _get_validate_code(self):
        """
        验证码识别结果处理机制：
            1. 先去除一些由于验证码识别错误而导致的特殊字符
            2. 验证识别结果是不是四个字符
            两个条件符合在进行登陆
        这里为了减少用错误的验证码去登陆教务系统的次数从而减少登陆时间
        """
        while True:
            wrong_chars = ' _-+|.:\';'
            correct_chars = string.ascii_lowercase + string.digits

            validate_url = 'http://jwgl.ouc.edu.cn/cas/genValidateCode'
            r = self.session.get(validate_url, headers=self.headers)
            f = open('temp.png', 'wb')
            f.write(r.content)
            f.close()
            validate_code = self._image_to_text('temp.png')
            # os.remove('temp.png')
            validate_code = validate_code.lower()
            print('[*] validate_code:' + validate_code)
            self.valicode_code_num = self.valicode_code_num + 1
            """
            由于无法确定验证码的准确性，所以当输入错误的用户名或者密码时，我们无法验证是什么原因导致的登陆失败
            这里我们认定当获得25次验证码后还未成功，就默认用户名或者密码错误
            """
            if self.valicode_code_num >= 25:
                return False

            for c in wrong_chars:
                validate_code = validate_code.replace(c, '')
            if len(validate_code) == self.validate_code_len:
                for i in validate_code:
                    if i not in correct_chars:
                        continue
                return validate_code

    def _login(self, validate_code):
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36''',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'http://jwgl.ouc.edu.cn/cas/login.action'
        }
        print(self.session.cookies)
        sessionid = self.session.cookies['JSESSIONID']
        rand_number = validate_code  # 验证码
        password_policy = '1'
        p_username = '_u' + rand_number
        p_password = '_p' + rand_number

        password = hashlib.md5(((hashlib.md5(self.password.encode('utf-8'))).hexdigest() + (
            hashlib.md5(rand_number.lower().encode('utf-8'))).hexdigest()).encode('utf-8')).hexdigest()
        username = base64.b64encode((self.username + ";;" + sessionid).encode('utf-8')).decode('utf-8')
        data = {
            p_username: username,
            p_password: password,
            'randnumber': rand_number,
            'isPasswordPolicy': password_policy
        }
        # proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
        try:
            self.session.post(self.login_url, headers=headers, data=data)
            r = self.session.get('http://jwgl.ouc.edu.cn/MainFrm.html', allow_redirects=False)
            print('[*] HTTP statue_code:' + str(r.status_code))
            if r.status_code == 200:
                print('[+] Validate_code accuracy: ' + str(round(100 / self.valicode_code_num, 2)) + '%')
                print('[+] Get validated cookie: ' + str(self.session.cookies.get_dict()))
                return True
        except Exception as e:
            print(e)

        return False

    def get_cookies(self):
        while True:
            code = self._get_validate_code()
            if code:
                if self._login(code):
                    return self.session.cookies
            else:
                return False

    def test(self, num):
        flag = 0
        while True:
            print(self.valicode_code_num)
            if self.valicode_code_num > num:
                break
            if self._login(self._get_validate_code()):
                flag = flag + 1

        print(str(flag / self.valicode_code_num))


class Data:
    def __init__(self, cookies):
        self.cookies = cookies

    def get_lessons_by_week(self, week=None):
        lessons_url = 'http://jwgl.ouc.edu.cn/frame/desk/showLessonScheduleDetailJson.action'
        headers = {
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36'''
        }
        if week:
            params = {
                'jxz': week
            }
            r = requests.get(lessons_url, params=params, headers=headers, cookies=self.cookies)
        else:
            r = requests.get(lessons_url, headers=headers, cookies=self.cookies)

        if r.status_code == 200:
            print('[+] get course!')
            soup = BeautifulSoup(r.text, 'html.parser')

        # 分析数据
        lessons = []
        tbody = soup.body.table.tbody
        trs = tbody.findAll('tr')
        for tr in trs:
            time_lesson_list = []
            tds = tr.findAll('td')
            for td in tds:
                text = td.getText()
                # u'\xa0' == &nbsp html实体编码中的空格
                text = text.replace('\t', '').replace('\r', '').replace('\n', '').replace(u'\xa0', 'null')
                text = text.strip(' ')
                if len(text) > 2:  # 去掉时间和第几节课
                    time_lesson_list.append(text)
            lessons.append(time_lesson_list)

        json_data = json.dumps(lessons, ensure_ascii=False)  # 不使用ascii编码，中文就能显示
        return json_data

    def get_grades(self, username):
        """
        此操作具有越权漏洞
        :param username: 学号
        :return: json数据
        """
        grades_url = 'http://jwgl.ouc.edu.cn/student/xscj.stuckcj_data.jsp'
        headers = {
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36''',
            'Referer': 'http://jwgl.ouc.edu.cn/student/xscj.stuckcj.jsp?menucode=JW130705'
        }
        params = 'xn=2018&xn1=2019&xq=1&ysyx=yscj&sjxz=sjxz1&userCode=' + username + '&ysyxS=on&sjxzS=on'
        encrypt_url = 'http://jwgl.ouc.edu.cn/custom/js/SetKingoEncypt.jsp'
        r = requests.get(encrypt_url, headers=headers, cookies=self.cookies)
        des_key = r.text.split(';')[0].split('\'')[1]
        timestamp = r.text.split(';')[1].split('\'')[1]
        token = hashlib.md5(((hashlib.md5(params.encode('utf-8'))).hexdigest() + (
            hashlib.md5(timestamp.encode('utf-8'))).hexdigest()).encode('utf-8')).hexdigest()
        params = base64.b64encode(
            (des_enc.utf16to8((des_enc.desEnc(params, des_key, None, None)))).encode('utf-8')).decode('utf-8')
        r = requests.get(grades_url, headers=headers, params={'params': params, 'token': token, 'timestamp': timestamp},
                         cookies=self.cookies)
        if r.status_code == 200:
            print('[+] get grades!')
            print(r.text)
            soup = BeautifulSoup(r.text, 'html.parser')

            # 分析数据
            all_course_grades = []
            tables = soup.body.findAll('table')
            for table in tables:
                if table.tbody:  # 异常处理很重要
                    tbody = table.tbody
                    trs = tbody.findAll('tr')
                    for tr in trs:
                        tds = tr.findAll('td')
                        course_name = tds[1].getText().split(']')[1]
                        course_credit = tds[2].getText()
                        course_grade = tds[6].getText()

                        all_course_grades.append([course_name, course_credit, course_grade])
            json_data = json.dumps(all_course_grades, ensure_ascii=False)  # 不使用ascii编码，中文就能显示
            return json_data
        return False

    def get_exam(self, username):
        """
        此操作具有越权漏洞
        :param username: 学号
        :return: json数据
        """
        exam_url = 'http://jwgl.ouc.edu.cn/taglib/DataTable.jsp?tableId=2538'
        headers = {
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36''',
            'Referer': 'http: // jwgl.ouc.edu.cn / student / ksap.ksapb.html?menucode = JW130603'
        }
        data = {
            'initQry': '0',
            'xh': username,
            'xn': '2018',
            'xq': '1',
            'xnxq': '2018-1',
            'kslcdm': '2'
        }
        r = requests.post(exam_url, headers=headers, data=data, cookies=self.cookies)
        if r.status_code == 200:
            print('[+] get exam!')
            soup = BeautifulSoup(r.text, 'html.parser')
            #print(soup)
            try:
                exams = []
                tbody = soup.table.tbody
                trs = tbody.findAll('tr')
                for tr in trs:
                    tds = tr.findAll('td')
                    course_name = tds[1].getText().split(']')[1]
                    exam_time = tds[6].getText()
                    exam_room = tds[7].getText()
                    exam_seat = tds[8].getText()
                    exams.append([course_name, exam_time, exam_room, exam_seat])

                json_data = json.dumps(exams, ensure_ascii=False)  # 不使用ascii编码，中文就能显示
                return json_data
            except:
                return False

