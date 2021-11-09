import os
import socket
import threading
import AES256module
from Crypto.PublicKey import RSA

import receive_message
from Crypto import Random

# 서버 연결정보; 자체 서버 실행시 변경 가능
import msg_changer

SERVER_HOST = "homework.islab.work"
SERVER_PORT = 8080

connectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connectSocket.connect((SERVER_HOST, SERVER_PORT))

key = Random.get_random_bytes(32)  # 보낼 때 쓸 키. 받았을 땐 갱신하면 됨.
iv = Random.get_random_bytes(16)

def createKey():
    private_key = RSA.generate(2048)
    f = open('myprivkey.pem', 'wb+')
    f.write(private_key.exportKey('PEM'))
    f.close()


if not os.path.isfile('myprivkey.pem'):
    createKey()
f = open('myprivkey.pem')
pub_key = RSA.importKey(f.read()).publickey().exportKey()
print("My RSA Public Key:", pub_key)
print("My AES Key:", key)
print("My AES IV:", iv)


def socket_read():
    while True:
        readbuff = connectSocket.recv(2048)

        if len(readbuff) == 0:
            continue

        recv_payload = readbuff.decode('utf-8')
        parse_payload(recv_payload)


def socket_send():
    while True:
        message = msg_changer.text_changer()
        connectSocket.sendall(message)


def parse_payload(payload):
    # 수신된 페이로드를 여기서 처리; 필요할 경우 추가 함수 정의 가능
    print(payload)
    receive_message.decode_msg(payload)
    splited_payload = payload.split('\n')
    # if 'KEYXCHG' in splited_payload[0] and ('Algo:AES-256-CBC' in payload or 'Algo: AES-256-CBC' in payload):
    #     key = splited_payload[-2]
    #     iv = splited_payload[-1]
    if 'MSGRECV' in splited_payload[0]:
        AES256module.AES256Decrypt(payload[-1], key, iv)


def decrypt(payload):
    AES256module.AES256Decrypt(payload, key, iv)


reading_thread = threading.Thread(target=socket_read)
sending_thread = threading.Thread(target=socket_send)

reading_thread.start()
sending_thread.start()

reading_thread.join()
sending_thread.join()