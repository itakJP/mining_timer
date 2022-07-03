from datetime import datetime
from time import mktime
import uuid
import hmac
import requests
import json
from hashlib import sha256
import sys
import configparser

############################## init ##############################
inipath = "./mining_timer.ini"
ini = configparser.ConfigParser()
ini.read(inipath, 'UTF-8')

#[SETTINGS]
org = ini['SETTINGS']['Organization_ID']
key = ini['SETTINGS']['API_Key_Code']
secret = ini['SETTINGS']['API_Secret_Key_Code']
rigids = ini['SETTINGS']['RIG_IDS']

host = "https://api2.nicehash.com"

##################################################################

def request(method, path, query, body):

    xtime = get_epoch_ms_from_now()
    xnonce = str(uuid.uuid4())

    message = bytearray(key, 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray(str(xtime), 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray(xnonce, 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray(org, 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray(method, 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray(path, 'utf-8')
    message += bytearray('\x00', 'utf-8')
    message += bytearray(query, 'utf-8')

    if body:
        body_json = json.dumps(body)
        message += bytearray('\x00', 'utf-8')
        message += bytearray(body_json, 'utf-8')

    digest = hmac.new(bytearray(secret, 'utf-8'), message, sha256).hexdigest()
    xauth = key + ":" + digest

    headers = {
        'X-Time': str(xtime),
        'X-Nonce': xnonce,
        'X-Auth': xauth,
        'Content-Type': 'application/json',
        'X-Organization-Id': org,
        'X-Request-Id': str(uuid.uuid4())
    }

    s = requests.Session()
    s.headers = headers

    url = host + path

    if body:
        response = s.request(method, url, data=body_json)
    else:
        response = s.request(method, url)

    if response.status_code == 200:
        return response.json()
    elif response.content:
        raise Exception(str(response.status_code) + ": " + response.reason + ": " + str(response.content))
    else:
        raise Exception(str(response.status_code) + ": " + response.reason)

def get_epoch_ms_from_now():
        now = datetime.now()
        now_ec_since_epoch = mktime(now.timetuple()) + now.microsecond / 1000000.0
        return int(now_ec_since_epoch * 1000)


def main(args):
    method = "POST"
    path = "/main/api/v2/mining/rigs/status2"
    rigs = rigids.split(",")
    if args[1] == "START":
        for rig in rigs:
            body = {
                "rigId":rig,
                "action":"START"
            }
            try:
                response = request(method, path, "", body)
            except Exception as ex:
                print("Unexpected error:", ex)
                sys.exit(1)

    elif args[1] == "STOP":
        for rig in rigs:
            body = {
                "rigId":rig,
                "action":"STOP"
            }
            try:
                response = request(method, path, "", body)
            except Exception as ex:
                print("Unexpected error:", ex)
                sys.exit(1)
    else:      
        sys.exit(2)

    print(response)
    sys.exit(0)

if __name__ == '__main__':
    sys.exit(main(sys.argv))