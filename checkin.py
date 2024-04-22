import argparse
import base64
import re
import time
import random
import traceback
import json

import requests
import rsa

TOKEN = ""


# 发送push+通知
def send_notification_by_pushplus(token: str, msg: str, title: str = "[天翼云盘自动签到+抽奖]"):
    if (not token) or (len(token) < 32) or (not msg):
        print("token或msg为空，放弃pushplus推送")
        return
    try:
        # 发送内容
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
        print(f'pushplus 推送异常: {str(e)}')
        print(traceback.format_exc())


def notify_user(token: str, msg: str, title: str = "[天翼云盘自动签到+抽奖]"):
    send_notification_by_pushplus(token, msg, title)


class CheckIn(object):
    client = requests.Session()
    submit_login_url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    sign_url = ("https://api.cloud.189.cn/mkt/userSign.action?rand=%s"
                "&clientType=TELEANDROID&version=8.6.3&model=SM-G930K")

    def __init__(self, username, password):
        self.username = username
        self.password = password

    @staticmethod
    def random_delay(min_sec=4, max_sec=8):
        if (min_sec < 1) or (max_sec > 60):
            min_sec = 4
            max_sec = 8
        random_seconds = random.randint(min_sec, max_sec)
        print(f"now delay {random_seconds}s")
        time.sleep(random_seconds)

    def check_in(self):
        self.login()
        CheckIn.random_delay()
        msg_notify = ""
        rand = str(round(time.time() * 1000))
        url = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
        url2 = "https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN"
        url3 = 'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_2022_FLDFS_KJ&activityId=ACT_SIGNIN'
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
        response = self.client.get(self.sign_url % rand, headers=headers, timeout=5)
        response_json = response.json()
        net_disk_bonus = response_json["netdiskBonus"]
        tip_sign_msg = "未" if response_json['isSign'] is False else "已"
        print(f"{tip_sign_msg}签到，签到获得{net_disk_bonus}M空间")
        msg_notify += f"{tip_sign_msg}签到，签到获得{net_disk_bonus}M空间, 签到时间：{response_json['signTime']}"
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
        response = self.client.get(url, headers=headers, timeout=5)
        if "errorCode" in response.text:
            print(f"抽奖1 error: {response.text}")
        else:
            response_json = response.json()
            prize_name = response_json['prizeName']
            print(f"抽奖1获得 {prize_name}")
            msg_notify += f"\n第1次获得：{prize_name} ，返回结果：{response.text}"

        CheckIn.random_delay(min_sec=8, max_sec=12)
        response = self.client.get(url2, headers=headers, timeout=5)
        if "errorCode" in response.text:
            print(f"抽奖2 error: {response.text}")
        else:
            response_json = response.json()
            prize_name = response_json['prizeName']
            print(f"抽奖2获得 {prize_name}")
            msg_notify += f"\n第2次获得：{prize_name} ，返回结果：{response.text}"

        CheckIn.random_delay(min_sec=8, max_sec=12)
        response = self.client.get(url3, headers=headers, timeout=5)
        if "errorCode" in response.text:
            print(f"抽奖3 error: {response.text}")
        else:
            response_json = response.json()
            prize_name = response_json['prizeName']
            print(f"抽奖3获得 {prize_name}")
            msg_notify += f"\n第3次获得：{prize_name} ，返回结果：{response.text}"
        notify_user(token=TOKEN, msg=msg_notify, title=f"天翼云签到")

    @staticmethod
    def rsa_encode(rsa_key, string):
        rsa_key = f"-----BEGIN PUBLIC KEY-----\n{rsa_key}\n-----END PUBLIC KEY-----"
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
        result = b64_to_hex((base64.b64encode(rsa.encrypt(f"{string}".encode(), pubkey))).decode())
        return result

    def login(self):
        # https://m.cloud.189.cn/login2014.jsp?redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html
        url = ""
        url_token = "https://m.cloud.189.cn/udb/udb_login.jsp?pageId=1&pageKey=default&clientType=wap&redirectURL=https://m.cloud.189.cn/zhuanti/2021/shakeLottery/index.html"
        # s = requests.Session()
        r = self.client.get(url_token, timeout=5)
        pattern = r"https?://[^\s'\"]+"  # 匹配以http或https开头的url
        match = re.search(pattern, r.text)  # 在文本中搜索匹配
        if match:  # 如果找到匹配
            url = match.group()  # 获取匹配的字符串
            # print(url)  # 打印url
        else:  # 如果没有找到匹配
            print("没有找到url")

        r = self.client.get(url, timeout=5)
        # print(r.text)
        pattern = r"<a id=\"j-tab-login-link\"[^>]*href=\"([^\"]+)\""  # 匹配id为j-tab-login-link的a标签，并捕获href引号内的内容
        match = re.search(pattern, r.text)  # 在文本中搜索匹配
        if match:  # 如果找到匹配
            href = match.group(1)  # 获取捕获的内容
            # print("href:" + href)  # 打印href链接
        else:  # 如果没有找到匹配
            print("没有找到href链接")
            raise Exception("no href link on login")

        r = self.client.get(href, timeout=5)
        captcha_token = re.findall(r"captchaToken' value='(.+?)'", r.text)[0]
        lt = re.findall(r'lt = "(.+?)"', r.text)[0]
        return_url = re.findall(r"returnUrl= '(.+?)'", r.text)[0]
        param_id = re.findall(r'paramId = "(.+?)"', r.text)[0]
        j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', r.text, re.M)[0]
        self.client.headers.update({"lt": lt})

        username = self.rsa_encode(j_rsakey, self.username)
        password = self.rsa_encode(j_rsakey, self.password)
        url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0"
                          ".3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientI"
                          "d/355325117317828 clientModel/SM-G930K imsi/460071114317824 cl"
                          "ientChannelId/qq proVersion/1.0.6",
            'Referer': 'https://open.e.189.cn/',
        }
        data = {
            "appKey": "cloud",
            "accountType": '01',
            "userName": f"{{RSA}}{username}",
            "password": f"{{RSA}}{password}",
            "validateCode": "",
            "captchaToken": captcha_token,
            "returnUrl": return_url,
            "mailSuffix": "@189.cn",
            "paramId": param_id
        }
        r = self.client.post(url, data=data, headers=headers, timeout=5)
        if r.json()['result'] == 0:
            print(f"login成功:{r.json()['msg']}")
        else:
            print(f"login失败:{r.json()['msg']}")
        redirect_url = r.json()['toUrl']
        self.client.get(redirect_url, timeout=5)
        # return s


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
    parser.add_argument('--username', type=str, help='账号(手机号)')
    parser.add_argument('--password', type=str, help='密码')
    parser.add_argument('--token', type=str, help='PushPlus推送Token')
    args = parser.parse_args()
    TOKEN = args.token
    helper = CheckIn(args.username, args.password)
    helper.check_in()
