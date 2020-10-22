import pyotp
import getpass
import os
import argparse
import configparser
import json
from pathlib import Path, PurePath
from crypto import encrypt_password, decrypt_password

def _parse_args():
    parser = argparse.ArgumentParser(description='Auto connect to iService1. You can use "ssh" or "scp" features.')
    parser.add_argument('-s','--src', type=Path, default=None,
            help='path of source file(used for scp), can be either absolute or relative path')
    parser.add_argument('-t','--tgt', type=Path, default=None,
            help='path of target file(used for scp), can be either absolute or relative path')
    parser.add_argument('-p', '--pss', action='store_true',
            help='Set this flag to fill in the password by your own, otherwise use the stored encrypted password')
    parser.add_argument('-g', '--generate', action='store_true',
            help='Set this flag to generate new key and store the encrypted password')
    #  parser.add_argument('--safe', action='store_true',
            #  help='Set this flag to use the setuid() feature with safety, which is experimental')
    parser.add_argument('-u', "--user", type=str, default="username",
            help="Type the username on iService1")
    args = parser.parse_args()
    return args
def check_config(args, script_dir, logger=None):
    config_dir = PurePath(script_dir / '../config')
    print('config_dir:', config_dir)
    if not os.path.exists(config_dir):
        print('Create config directory')
        os.makedirs(config_dir)
    if args.user == None:
        # find username in config files
        print("username is None")
        exit(1)
    otp_path = config_dir / "otp.json"
    if not os.path.exists(otp_path):
        print("otp file not exists!")
        exit(1)
    else:
        with open(otp_path, 'r') as f:
            users_otp = json.load(f)
        otp_key = users_otp.get(args.user)
        print("otp_key:", otp_key)
        if otp_key == None:
            print("Username doesn't have correspond otp key")
            exit(1)
    user_config_path = config_dir / Path(args.user+'.ini')
    config = configparser.ConfigParser()
    if not os.path.exists(user_config_path):
        print("Config .ini not exists")
        config[args.user] = {
                "otp_key": otp_key
                }
        update_password(args, config, user_config_path, logger)

    else:
        config.read(user_config_path)
        if args.generate:
            update_password(args, config, user_config_path, logger)

    #  else:
        #  print('Exist!')
    return config

def update_password(args, config, user_config_path, logger=None):
    args.update = True
    user = getpass.getuser() 
    pss = getpass.getpass("Username: %s\nPassword:"%(user)) 
    key, token = encrypt_password(pss)
    config[args.user]['key'] = key
    config[args.user]['token'] = token
    with open(user_config_path, 'w') as f:
        config.write(f)

if __name__ == '__main__':
    args = _parse_args()
    script_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    print('script_dir:',script_dir)
    args.update = False
    config = check_config(args, script_dir)
    pss = decrypt_password(config[args.user]['key'], config[args.user]['token'])
    if args.pss and not args.update:
        user = getpass.getuser() 
        pss = getpass.getpass("Username: %s\nFill in your password manually:"%(user)) 
    otp_code = pyotp.TOTP(config[args.user]['otp_key'])
    pssOtp = pss + otp_code.now().strip()
    #  print("pssOtp:", pssOtp)
    os.system("sshpass -p \"%s\" ssh %s@ln01.twcc.ai"%(pssOtp, args.user))

    #  print('password =', pss)

    
#  otp_key = "Q47THR6X4A6RQE5SWBL3YXD4N27G7NOP65SNGP36DBKZ7R5HMBMA===="
#  otp_code = pyotp.TOTP(otp_key)

#  user = getpass.getuser() 
#  pss = getpass.getpass("Username: %s\nPassword:"%(user)) 

#  pssOtp = pss + otp_code.now().strip()

#  os.system("sshpass -p \"%s\" ssh darren1629@ln01.twcc.ai"%(pssOtp))
