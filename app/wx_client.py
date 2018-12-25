# -*- coding:utf-8 -*-
import requests
import json
from app.config import *


class WXClient:
    def __init__(self):
        token_url = 'https://api.weixin.qq.com/cgi-bin/token'
        params = {
            'grant_type': 'client_credential',
            'appid': appid,
            'secret': secret
        }
        r = requests.get(token_url, params=params)
        access_token = json.loads(r.text)['access_token']
        print('[+] access_token: ' + access_token)
        self.access_token = access_token

    def set_menu(self, menu_path):
        # delete_url = 'https://api.weixin.qq.com/cgi-bin/menu/get?access_token=' + self.access_token
        # r = requests.get(delete_url)
        with open(menu_path, encoding='utf-8') as f:
            menu_json = f.read()
        f.close()
        create_url = 'https://api.weixin.qq.com/cgi-bin/menu/create?access_token=' + self.access_token
        r = requests.post(create_url, data=menu_json.encode('utf-8'))
        print(r.text)

    def update_remark(self, openid, remark):
        update_url = 'https://api.weixin.qq.com/cgi-bin/user/info/updateremark?access_token' + self.access_token
        data = {
            'openid': openid,
            'remark': remark
        }
        r = requests.post(update_url, data=data)
        print(r.text)
