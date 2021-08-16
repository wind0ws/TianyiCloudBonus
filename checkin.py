import argparse
import base64
import re
import time
import traceback
import sys
import json

import requests
import rsa

TOKEN=""

#发送push+通知
def sendPushplus(token: str, msg: str, title:str="[天翼云盘自动签到+抽奖]"):
    if (not token) or (len(token) < 32) or (not msg):
      print("token或msg为空，放弃pushplus推送")
      return
    try:
        #发送内容
        data = {
            "token": token,
            "title": title,
            "content": msg
        }
        url = 'http://www.pushplus.plus/send'
        headers = {'Content-Type': 'application/json'}
        body = json.dumps(data).encode(encoding='utf-8')
        resp = requests.post(url, data=body, headers=headers)
        print(f"pushplus 推送结果：{resp} => {resp.text}")
    except Exception as e:
        print(f'pushplus 推送异常，原因为: {str(e)}')
        print(traceback.format_exc())

def notify_user(token: str, msg: str, title:str="[天翼云盘自动签到+抽奖]"):
    sendPushplus(token, msg, title)

class CheckIn(object):
    client = requests.Session()
    login_url = "https://cloud.189.cn/api/portal/loginUrl.action?" \
                "redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action"
    submit_login_url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    sign_url = ("https://api.cloud.189.cn/mkt/userSign.action?rand=%s"
                "&clientType=TELEANDROID&version=8.6.3&model=SM-G930K")

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def check_in(self):
        self.login()
        rand = str(round(time.time() * 1000))
        url = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
        url2 = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN"
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv)"
                          " AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74"
                          ".0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clie"
                          "ntId/355325117317828 clientModel/SM-G930K imsi/46007111431782"
                          "4 clientChannelId/qq proVersion/1.0.6",
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }
        response = self.client.get(self.sign_url % rand, headers=headers)
        resonseJson = response.json()
        net_disk_bonus = resonseJson["netdiskBonus"]
        tip_sign_msg = "未" if resonseJson['isSign'] == False else "已"
        print(f"{tip_sign_msg}签到，签到获得{net_disk_bonus}M空间")
        notify_user(token=TOKEN, msg=f"{tip_sign_msg}签到，签到获得{net_disk_bonus}M空间, 签到时间：{resonseJson['signTime']}", title=f"天翼云签到{net_disk_bonus}M")
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0"
                          ".3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientI"
                          "d/355325117317828 clientModel/SM-G930K imsi/460071114317824 cl"
                          "ientChannelId/qq proVersion/1.0.6",
            "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
            "Host": "m.cloud.189.cn",
            "Accept-Encoding": "gzip, deflate",
        }
        response = self.client.get(url, headers=headers)
        if "errorCode" in response.text:
            print(response.text)
        else:
            responseJson = response.json()
            print(f"抽奖1获得{responseJson}")
            prizeName = responseJson['prizeName']
            notify_user(token=TOKEN, msg=f"天翼云盘第一次抽奖获得：{prizeName} ，返回结果：{response.text}", title=f"天翼抽奖1获得{prizeName}")
            
        response = self.client.get(url2, headers=headers)
        if "errorCode" in response.text:
            print(response.text)
        else:
            responseJson = response.json()
            print(f"抽奖2获得{responseJson}")
            prizeName = responseJson['prizeName']
            notify_user(token=TOKEN, msg=f"天翼云盘第二次抽奖获得：{prizeName} ，返回结果：{response.text}", title=f"天翼抽奖2获得{prizeName}")

    @staticmethod
    def rsa_encode(rsa_key, string):
        rsa_key = f"-----BEGIN PUBLIC KEY-----\n{rsa_key}\n-----END PUBLIC KEY-----"
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        result = b64_to_hex((base64.b64encode(rsa.encrypt(f"{string}".encode(), pubkey))).decode())
        return result

    def login(self):
        r = self.client.get(self.login_url)
        captcha_token = re.findall(r"captchaToken' value='(.+?)'", r.text)[0]
        lt = re.findall(r'lt = "(.+?)"', r.text)[0]
        return_url = re.findall(r"returnUrl = '(.+?)'", r.text)[0]
        param_id = re.findall(r'paramId = "(.+?)"', r.text)[0]
        j_rsa_key = re.findall(r'j_rsaKey" value="(\S+)"', r.text, re.M)[0]
        self.client.headers.update({"lt": lt})
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0",
            "Referer": "https://open.e.189.cn/",
        }
        data = {
            "appKey": "cloud",
            "accountType": "01",
            "userName": f"{{RSA}}{self.rsa_encode(j_rsa_key, self.username)}",
            "password": f"{{RSA}}{self.rsa_encode(j_rsa_key, self.password)}",
            "validateCode": "",
            "captchaToken": captcha_token,
            "returnUrl": return_url,
            "mailSuffix": "@189.cn",
            "paramId": param_id,
        }
        r = self.client.post(self.submit_login_url, data=data, headers=headers, timeout=5)
        if r.json()["result"] == 0:
            print(r.json()["msg"])
        else:
            print(r.json()["msg"])
        redirect_url = r.json()["toUrl"]
        self.client.get(redirect_url)


def _chr(a):
    return "0123456789abcdefghijklmnopqrstuvwxyz"[a]


b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64_to_hex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = b64map.index(list(a)[i])
            if 0 == e:
                e = 1
                d += _chr(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += _chr(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += _chr(c)
                d += _chr(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += _chr(c << 2 | v >> 4)
                d += _chr(15 & v)
    if e == 1:
        d += _chr(c << 2)
    return d


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='天翼云签到脚本')
    parser.add_argument('--username', type=str, help='账号')
    parser.add_argument('--password', type=str, help='密码')
    parser.add_argument('--token', type=str, help='PushPlus推送Token')
    args = parser.parse_args()
    TOKEN = args.token
    helper = CheckIn(args.username, args.password)
    helper.check_in()

