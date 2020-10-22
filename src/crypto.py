from cryptography.fernet import Fernet
import configparser
import time

def encrypt_password(pss):
# pss is a string
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(str.encode(pss))
    return bytes.decode(key), bytes.decode(token)
def decrypt_password(key, token):
    # key, token are strings
    f = Fernet(str.encode(key))
    pss = f.decrypt(str.encode(token))
    return bytes.decode(pss)
#  print('key:', key)
#  print('token:', token)
#  print("text:",f.decrypt(token))

#  config = configparser.ConfigParser()
#  config['test'] = {
        #  "key": bytes.decode(key),
        #  "token": bytes.decode(token)
        #  }
#  with open('test.ini', 'w') as configfile:
    #  config.write(configfile)
#  del config
#  print("----loading----")
#  time.sleep(5)
#  config = configparser.ConfigParser()
#  config.read('test.ini')
#  key = str.encode(config['test']['key'])
#  token = str.encode(config['test']['token'])
#  print('key:', key)
#  print('token:', token)
#  print("text:",f.decrypt(token))

