import base64
import json
import time
import uuid
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

def get_secret(data):
    public_key = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkmujpECrpxvCCF5iHnXDhSb4a8OODNg7x2dUggK0JNWzbw3Oz30aIZxzXm0dfVTRhuO+Upv0gtkwx5WVW1oLzwxAcQwmWx5G0F5B3yglsGZoDJZwgZmp7zrowOkyR59zKy4CHwbjwcxaSBVXtJ/NIZ21x63p663Nxjj1ZTIkl3wIDAQAB'

    try:
        public_key_bytes = base64.b64decode(public_key)
        public_key = serialization.load_der_public_key(
            public_key_bytes,
            backend=default_backend()
        )
        encrypted = public_key.encrypt(
            data.encode('utf-8'),
            padding.PKCS1v15()
        )

        return base64.b64encode(encrypted).decode('utf-8')
    except Exception as e:
        print(e)
        return None

def rsa_decrypt(private_key_str: str, ciphertext_base64: str) -> str:
    try:
        # 解码私钥
        private_key = serialization.load_der_private_key(
            base64.b64decode(private_key_str),
            password=None,
            backend=default_backend()
        )

        # 解码密文并解密
        plaintext = private_key.decrypt(
            base64.b64decode(ciphertext_base64),
            padding.PKCS1v15()
        )

        return plaintext.decode('utf-8')

    except Exception as e:
        print("解密失败:", e)
        return None

def aes_encrypt(plaintext: str, key: str, mode='CBC', iv=None) -> str:
    """
    AES加密（返回Base64字符串）
    :param plaintext: 明文文本
    :param key: 加密密钥（任意长度字符串）
    :param mode: 加密模式（CBC或ECB）
    :param iv: 初始化向量（CBC模式需要16字节字符串，默认全零）
    :return: Base64编码的密文
    """
    key_bytes = key.encode('utf-8')
    # 处理IV（CBC模式需要16字节）
    iv_bytes = iv.encode() if iv else b'\0' * 16

    # 加密逻辑
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    if mode.upper() == 'CBC':
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    elif mode.upper() == 'ECB':
        cipher = AES.new(key_bytes, AES.MODE_ECB)
    else:
        raise ValueError("Unsupported mode, choose CBC or ECB")

    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(key: str, source: str) -> str:
    # 密钥转字节
    key_bytes = key.encode('utf-8')

    ciphertext = base64.b64decode(source)

    cipher = AES.new(key_bytes, AES.MODE_ECB)

    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    return plaintext.decode('utf-8')

rsa_de_key = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAK2obrvkb/npsEjqvvuJcVgGigOcdtvjGMGggufULIf6u4otOsofcBHdk3QZ2H/0qnf9Na7q6wmmE1+kuWJlEUO1/G/coBLrb3J3H7W6L2QR0dIYccEnD1P5qRaXdJvSWgSRIqzPQcP1A1a9BTwiDpQ9v77NTWGqi4JfbY24eI5TAgMBAAECgYABQd9vX9OJuS3sETsJwjB+ZSm5pffcVrQWrs1T1V7vKxsRgItU7E5Y6sRHCmrdXk2fqccqOYwzGS85uY0YD8hEtK580SCz1XKAgVqe/loPi7lYJH1W1xN29WWtS1JjNSN5HnPlWwQbGwkTxo1Om9u/SJ/fYphVXriwLP8bP+VCWQJBANOQJtRABQS4OYAHyyVbW6RBZ5d64Y/Kjhf1ZlIKRa9QDWCRlNg6XrJ0tZ5xt9RK1SDRZDniu6Eku3YHuI0/CJkCQQDSIhpNbDbS1554x1dO7oZATdufL+JVjZa/o6tqizslo5aoD7ahREuOh7e1mI4yDqmaA6jSsRL9OyG4a11lN8XLAkEAxe/kpEiRaW0DPyoLgpQLFY6r4Snyx5l3gCr05GT/9ZosKeGLJRLXbpeLJQa4O0MYTHAcGZxsd8PqL+/hVyVWYQJBAMFucxfiDXV41oAHv+8A0sRO52RaB9cJR0ORvjGNiRzUwdJi5JL+8y548DtR+1NI/AayZ63LItfInvnMm2SZOpECQFtjgv08sKNyKgFKOumAl55A4/Ai4LX7w1US2HGAeOJwL8G6nipePA8KbGBzjvXH9Lfr8GEuy1DdCxYcxhwnmWg="

headers = {

    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 14; 22041211AC Build/UP1A.231005.007)',
    'App-Version': '2.0.4',
    'App-Number': 'e8b34fabdf6f9562',
    'System-Type': 'Android',
    'Accept-Encoding': 'gzip',
}

login_url = 'http://111.230.160.82/v2/user/login'
ad_list_url = 'http://111.230.160.82/v2/advert/info/getAdvert'
ad_submit_url = 'http://111.230.160.82/v2/advert/info/advertSubmit'
fund_url = 'http://111.230.160.82/user/fund/getFund'
session = requests.session()
session.headers.update(headers)
key = str(uuid.uuid4()).replace('-', '')[:16]
print('key:', key)
def get_advert():
    key = str(uuid.uuid4()).replace('-', '')[:16]
    data = aes_encrypt('{"systemType":1}', key, mode='ECB')
    ad_list = session.post(url=ad_list_url, data=data,
                           headers={'Current': "1", 'Size': '10', 'Secret': get_secret(key)})

    respond_secret = ad_list.headers.get('Secret')
    aes_de_key = rsa_decrypt(rsa_de_key, respond_secret)
    return aes_decrypt(aes_de_key, ad_list.json()['data'])

def login(z, p):
    data = '{{"account":"{}","appKey":"android","code":"{}","inviteCode":"","type":2}}'.format(z, p)
    data = aes_encrypt(data, key, mode='ECB')
    respond = session.post(login_url, data=data, headers={'Secret': get_secret(key)})
    respond_secret = respond.headers.get('Secret')
    aes_de_key = rsa_decrypt(rsa_de_key, respond_secret)
    return json.loads(aes_decrypt(aes_de_key, respond.json()['data']))['accessToken']

def get_reward(advert):
    reward_info = {
        "advertNo": advert['advertNo'],
        "costModel": advert['costModel'],
        "phoneBrand": 'Xiaomi',
        "platformCode": advert["platformCode"],
        "platformId": advert['platformId'],
        "spaceId": advert['spaceId'],
        "systemType": '1',
        "systemVersion": '10',
        "typeId": advert["typeId"],
        "typePlatformId": '0'
    }
    print(json.dumps(reward_info, separators=(',', ':'), ensure_ascii=False))
    data = aes_encrypt(json.dumps(reward_info, separators=(',', ':'), ensure_ascii=False), key=key, mode='ECB')
    # print(f"获取{advert['diamond']}颗钻石 参数:{data}")
    time.sleep(5)
    respond = session.post(ad_submit_url, data, headers={'Secret': get_secret(key)})
    print(respond.json())
    return int(advert['diamond']) if respond.json()['success'] else 0

def get_fund():
    respond = session.get(fund_url, headers={'Secret': get_secret(key)})
    return respond.json()

target_count = 80
count = 0
result = login("xxxxx",'xxxxxxx')
session.headers.update({'Authorization': 'Bearer ' + result})
print(get_fund())

while count < target_count:
    ad_list = json.loads(get_advert())
    print(ad_list)
    for index in range(1, len(ad_list)):
        home = ad_list[index]['adverts']
        for advert in home:
            count += get_reward(advert)
            print('当前已获取钻石:', get_fund()['data']['quantity'])
            if count >= target_count:
                break
        if count >= target_count:
            break

