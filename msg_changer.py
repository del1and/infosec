import base64

from Crypto import Random

import AES256module
from Crypto.PublicKey import RSA

# 키를 보낼 땐 RSA로 보내고 AES키를 RSA로 암호화해서 보냄

# 메시지를 보낼 땐 받은 AES키로 암호화
"""
def createKey():
    private_key = RSA.generate(2048)
    f = open('myprivkey.pem', 'wb+')
    f.write(private_key.exportKey('PEM'))
    f.close()
"""

key = Random.get_random_bytes(32)
def readKey():
    h = open('myprivkey.pem', 'r')
    key = RSA.importKey(h.read())
    h.close()
    return key


def body_decryption(msg):
    private_key = readKey()
    decrypted_msg = private_key.decrypt(msg)

    return decrypted_msg


def body_encryption(msg, key):
    pub_key = RSA.importKey(key)  # 받은 공개키
    print(pub_key)
    encd_text = pub_key.encrypt(msg, 32)

    return encd_text


def text_changer():
    """
    순서: RSA 키가 없으면 생성, AES 키와 IV는 Crypto 의 Random Byte 로 생성.
    3EPROTO CONNECT 를 통해 연결 후 KEY 교환 (Alice(1): RSA, Bob(2): AES)
    키 교환용 암호화가 RSA, 메시지 교환용 암호화가 AES
    페이로드 구조: Preamble, Header, Body.
    Body 도 빈 값일 때 종료시켜야 할 듯함.
    """
    """
    if not os.path.isfile('myprivkey.pem'):
        createKey()
    """

    header_list = ['Algo', 'Timestamp', 'Nonce', 'From', 'To']
    message_list = []
    inv_slash_cnt = 0  # 메시지에서 필요없는 값 빼기 위함
    body_list = []
    while True:
        preamble = input('Preamble:')
        message_list.append(preamble)

        if preamble != '':
            while True:
                header = input('header:')
                if 'Credential' in header:
                    message_list.append(header)
                    break
                elif header == '':
                    message_list.append('')
                    break
                else:
                    try:
                        if header.split(':')[0] in header_list:
                            message_list.append(header)
                            continue
                    except:pass
        try:
            if 'Credential' in message_list[-1].split(':')[0]:
                break
        except:pass

        body = input('Body:')
        try:
            if (preamble.split()[1] == 'KEYXCHG' or preamble.split()[1] == 'KEYXCHGRST') and \
                    ('Algo:RSA' in message_list or 'Algo: RSA' in message_list):
                # Method가 KEYXCHG이고 알고리즘이 RSA거나 AES를 판단
                print("RSA MODE")
                # body = bytes(body.encode('utf-8'))
                body_list.append(bytes(body.encode('utf-8')))
            elif (preamble.split()[1] == 'KEYXCHG' or preamble.split()[1] == 'KEYXCHGRST') and \
                    ('Algo: AES-256-CBC' in message_list or 'Algo:AES-256-CBC' in message_list):
                print("AES MODE")
                # body = body.encode('utf-8')
                # 키만 해결하면 됨
                # body = bytes(list(body_encryption(body, key=b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmsOQKbkWa7IfVvjXPhu5I08o3\nzaTuohwPijx0Oh93nf+zTNfLufLxDVK0qqRw29HnORn460ouOOxoMGcneUl9+UoV\nUPRsmZgKELNj/HVLqnuP/cRQpvdB2IjEwC7itrQ/JwMnOOmo22Da/6WyECNRyTdw\nZdi3R3/xvJKNSkBhPwIDAQAB\n-----END PUBLIC KEY-----'))[0])
                body_list.append(bytes(list(body_encryption(body, key=b'-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmsOQKbkWa7IfVvjXPhu5I08o3\nzaTuohwPijx0Oh93nf+zTNfLufLxDVK0qqRw29HnORn460ouOOxoMGcneUl9+UoV\nUPRsmZgKELNj/HVLqnuP/cRQpvdB2IjEwC7itrQ/JwMnOOmo22Da/6WyECNRyTdw\nZdi3R3/xvJKNSkBhPwIDAQAB\n-----END PUBLIC KEY-----'))[0]))
                # RSA 공개 키로 암호화..인데 받은 키로 암호화 해야함 Done.
            else:
                # 진짜 메시지면 이제 AES로 암호화해야함
                print(body)
                # body = AES256module.AES256Encrypt(key, body)
                # body_list.append(AES256module.AES256Encrypt(key, body))
                body_list.append(body)
        except: pass
        break

    # 전체 문장에 들어갔던 배열 변환
    final_message = '\\n'.join(message_list)
    # print(final_message)

    ascii_message = []
    # print('final_message:', final_message)
    # \n 기호 ASCII 10으로 변환 그러나 키 외의 바디는 변환해선 안 됨

    for i in range(len(final_message)):
        if final_message[i+inv_slash_cnt] != '\\':
            ascii_message.append(ord(final_message[i+inv_slash_cnt]))
        elif final_message[i+inv_slash_cnt:i+2+inv_slash_cnt] == '\\n':
            ascii_message.append(ord('\n'))
            inv_slash_cnt += 1
        if i+inv_slash_cnt == len(final_message)-1:
            break

    # ascii_message.append(0)  # 최종 결과물
    # print('ascii_message:', bytes(ascii_message))
    # body_enc = base64.b64encode(list(body_list))

    ascii_message = bytes(ascii_message)
    if preamble == '3EPROTO CONNECT' or preamble == '3EPROTO DISCONNECT':
        result = ascii_message+b'\x00'
    elif (preamble == '3EPROTO KEYXCHG' or preamble == '3EPROTO KEYXCHGRST') and\
         ('Algo:AES-256-CBC' in message_list or 'Algo: AES-256-CBC' in message_list):
        # result = ascii_message+str(body_list[0]).encode('utf-8')+str(body_list[1]).encode('utf-8')+b'\x00'
        result = ascii_message + str(body_list[0]).encode('utf-8')+b'\x00'
    elif (preamble == '3EPROTO KEYXCHG' or preamble == '3EPROTO KEYXCHGRST') and \
         ('Algo:RSA' in message_list or 'Algo: RSA' in message_list):
        result = ascii_message+body_list[0]+b'\x00'
    else:
        result = ascii_message+base64.b64encode(body_list[0])+b'\x00'

    return result
