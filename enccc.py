from Crypto.Cipher import AES
'''
data= 'hellooo'
key = b'Sixteen byte key'
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
ciphertext,tag= cipher.encrypt_and_digest(data.encode('utf-8'))
print(ciphertext)
'''
key = b'Sixteen byte key'
ciphertext='wȧ��'
cipher = AES.new(key, AES.MODE_EAX)
nonce = cipher.nonce
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)

print("The message is authentic:", plaintext)
