from Crypto.PublicKey import RSA
import base64

def readKey():
    h = open('myprivkey.pem', 'r')
    key = RSA.importKey(h.read())
    h.close()
    return key


def body_decryption(msg):
    private_key = readKey()
    decrypted_msg = private_key.decrypt(msg)

    return decrypted_msg


def decode_msg(payload):
    # print(payload)
    # payload = b'3EPROTO MSGSEND\nFrom:LJS\nTo:LJS\nawQVzRzuvzAYDAl4Eu+ONAWbCOQH+J1PJI2XEwqx49Dj7O/ECOhyP2qf5As7eZUAru6TYTye9eStmsVjPV6DYGv2hvL5fJSQN1R4ugGs8mhC83BIvX6gn9EdOnNK6OgQVGnNmn/6H3S06CgxYctmCj0MroE8iTWe0i4JakRLbnc=\x00'
    # payload = b'3EPROTO KEYXCHG\nAlgo:RSA\nFrom:LJS\nTo:LJA1\nLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRQ21zT1FLYmtXYTdJZlZ2alhQaHU1STA4bzNcbnphVHVvaHdQaWp4ME9oOTNuZit6VE5mTHVmTHhEVkswcXFSdzI5SG5PUm40NjBvdU9PeG9NR2NuZVVsOStVb1ZcblVQUnNtWmdLRUxOai9IVkxxbnVQL2NSUXB2ZEIySWpFd0M3aXRyUS9Kd01uT09tbzIyRGEvNld5RUNOUnlUZHdcblpkaTNSMy94dkpLTlNrQmhQd0lEQVFBQlxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t\x00'
    if payload.startswith('3EPROTO MSGRECV'):
        payload = payload.split('\n')
        last_payload = payload[-1][:-1]
        print(str(body_decryption(base64.b64decode(last_payload)))[2:-1])
    elif payload.startswith('3EPROTO KEYXCHG'):
        payload = payload.split('\n')[-1][:-1]
        print(base64.b64decode(payload))

