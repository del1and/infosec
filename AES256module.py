from Crypto.Cipher import AES


def AES256Encrypt(key, plain):
	# print(len(plain))
	length = AES.block_size - (len(plain) % AES.block_size)
	# print(length)
	plain += chr(length)*length
	# print(plain)
	encryptor = AES.new(key, AES.MODE_CBC, IV=iv)

	return encryptor.encrypt(plain)


def AES256Decrypt(key, iv, cipher):
	encryptor = AES.new(key, AES.MODE_CBC, IV=iv)
	plain = encryptor.decrypt(cipher)
	plain = plain[0:-ord(chr(plain[-1]))]

	return plain
#
# text = 'Hello, world.'
# print(len(text))
# print(iv)
# encrypted = AES256Encrypt(key, text)
# print(encrypted)
#
# print(AES256Decrypt(key, iv, encrypted))

# decrypted = AES256Decrypt(key, iv, encrypted)
# print(decrypted)

# AES는 보낼 때 새로 만들어서 보내니까
# 보내는 사람의 헤더가 Algo:AES-CBC-256이면
#
