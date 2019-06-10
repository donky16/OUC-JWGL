from flask import request
import hashlib

from app.wx_server import MsgReceive
from app import app
from app.models import *


@app.route('/', methods=['GET', 'POST'])
def main():
    """
     GET /?signature=8697f29de08ee3bfccc14a72e2a4e9abf2e157c0&echostr=5129591258879047566&timestamp=1545810822&nonce=1624905056
    :return:
    """
    if request.method == 'GET':
        token = 'weixin'
        data = request.args
        signature = data.get('signature', '')
        timestamp = data.get('timestamp', '')
        nonce = data.get('nonce', '')
        echo_str = data.get('echostr', '')
        params_list = [token, timestamp, nonce]
        params_list.sort()
        s = params_list[0] + params_list[1] + params_list[2]
        hashcode = hashlib.sha1(s.encode('utf-8')).hexdigest()
        if hashcode == signature:
            return echo_str
        else:
            return ""
    if request.method == 'POST':
        xml_data = request.data
        print('[+] receive msg:\n' + xml_data.decode('utf-8') + '\n')
        msg_receive = MsgReceive(xml_data)
        send_msg = msg_receive.deal()
        print('[+] send msg:\n' + send_msg)
        return send_msg


if __name__ == '__main__':
    db.create_all()
    app.run()
