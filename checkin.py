import requests, time, re, rsa, json, base64
import urllib.error
from urllib import parse

RESULT_SUCCESS = 0
mysession = requests.Session()

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

def main():
    username = ""
    password = ""
    TOKEN = ""
    if(username == "" or password == ""):
       username = input("账号：")
       password = input("密码：")

    if TOKEN == "":
       TOKEN = input("推送令牌(选填)：")
    
    if((not username) or (not password)):
       print("用户名或密码为空，放弃登陆")
       return
       
    try:
        login(username, password)
    except Exception as ex:
        notify_user(token=TOKEN, msg=f"登录失败{ex}")
        return

    rand = str(round(time.time()*1000))
    url_sign = f'https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K'
    url_bonus1 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN'
    url_bonus2 = f'https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN'
    headers = {
        'User-Agent':'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer" : "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host" : "m.cloud.189.cn",
        "Accept-Encoding" : "gzip, deflate",
    }
    response = mysession.get(url_sign, headers=headers)
    print(f"签到返回：{response.text}")
    resonseJson = response.json()
    netdiskBonus = resonseJson['netdiskBonus']
    tip_sign_msg = "未" if resonseJson['isSign'] == False else "已"
    print(f"{tip_sign_msg}签到，签到获得{netdiskBonus}M空间")
    notify_user(token=TOKEN, msg=f"{tip_sign_msg}签到，签到获得{netdiskBonus}M空间, 签到时间：{resonseJson['signTime']}", title=f"天翼云签到{netdiskBonus}M")
   
    headers = {
        'User-Agent':'Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6',
        "Referer" : "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host" : "m.cloud.189.cn",
        "Accept-Encoding" : "gzip, deflate",
    }
    response = mysession.get(url_bonus1, headers=headers)
    if ("errorCode" in response.text):
        print(f"第一次抽奖错误：{response.text}")
    else:
        responseJson = response.json()
        print(f"第一次抽奖返回：{responseJson}")
        prizeName = responseJson['prizeName']
        notify_user(token=TOKEN, msg=f"天翼云盘第一次抽奖获得：{prizeName}, ，返回结果：{response.text}", title=f"天翼抽奖1获得{prizeName}")
        
    response = mysession.get(url_bonus2, headers=headers)
    if ("errorCode" in response.text):
        print(f"第二次抽奖错误：{response.text}")
    else:
        responseJson = response.json()
        print(f"第二次抽奖返回：{responseJson}")
        prizeName = responseJson['prizeName']
        notify_user(token=TOKEN, msg=f"天翼云盘第二次抽奖获得：{prizeName}，返回结果：{response.text}", title=f"天翼抽奖2获得{prizeName}")


BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")
def int2char(a):
    return BI_RM[a]

b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = b64map.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(j_rsakey, string):
    rsa_key = f"-----BEGIN PUBLIC KEY-----\n{j_rsakey}\n-----END PUBLIC KEY-----"
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex((base64.b64encode(rsa.encrypt(f'{string}'.encode(), pubkey))).decode())
    return result

def calculate_md5_sign(params):
    return hashlib.md5('&'.join(sorted(params.split('&'))).encode('utf-8')).hexdigest()

def login(username, password):
    url = "https://cloud.189.cn/udb/udb_login.jsp?pageId=1&redirectURL=/main.action"
    resp = mysession.get(url)
    resp_text = resp.text
    captchaToken = re.findall(r"captchaToken' value='(.+?)'", resp_text)[0]
    lt = re.findall(r'lt = "(.+?)"', resp_text)[0]
    returnUrl = re.findall(r"returnUrl = '(.+?)'", resp_text)[0]
    paramId = re.findall(r'paramId = "(.+?)"', resp_text)[0]
    j_rsakey = re.findall(r'j_rsaKey" value="(\S+)"', resp_text, re.M)[0]
    mysession.headers.update({"lt": lt})

    username = rsa_encode(j_rsakey, username)
    password = rsa_encode(j_rsakey, password)
    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0',
        'Referer': 'https://open.e.189.cn/',
        }
    data = {
        "appKey": "cloud",
        "accountType": '01',
        "userName": f"{{RSA}}{username}",
        "password": f"{{RSA}}{password}",
        "validateCode": "",
        "captchaToken": captchaToken,
        "returnUrl": returnUrl,
        "mailSuffix": "@189.cn",
        "paramId": paramId
        }
    resp = mysession.post(url, data=data, headers=headers, timeout=5)
    resp_json = resp.json()
    msg = resp_json["msg"]
    if(resp_json['result'] == RESULT_SUCCESS):
        print(f"登陆成功：{msg}")
        redirect_url = resp_json.get('toUrl')
        if redirect_url is not None:
            resp = mysession.get(redirect_url)
            print(f"login redirect to {redirect_url}, resp => {resp.text}")
        else:
            print(f"登陆结果json中没有toUrl字段 => {resp_json}")
    else:
        print(f"登陆失败：{msg}, 详情：{resp_json}")
        notify_user(token=TOKEN, msg=f"天翼云登陆失败：{resp_json}", title="天翼云登陆失败")
    return mysession
    

if __name__ == "__main__":
    main()

