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
    parser.add_argument('-l','--local', type=Path, default=None,
            help='path of source file(used for scp), can be either absolute or relative path')
    parser.add_argument('-s','--server', type=Path, default=None,
            help='path of target file(used for scp), can be either absolute or relative path')
    parser.add_argument('-p', '--pss', action='store_true',
            help='Set this flag to fill in the password by your own, otherwise use the stored encrypted password')
    parser.add_argument('-g', '--generate', action='store_true',
            help='Set this flag to generate new key and store the encrypted password')
    #  parser.add_argument('--safe', action='store_true',
            #  help='Set this flag to use the setuid() feature with safety, which is experimental')
    parser.add_argument("--user", type=str, default=None,
            help="Type the username on iService1")
    parser.add_argument('-u','--upload', action='store_true',
            help='upload file to server')
    parser.add_argument('-d', '--download', action='store_true',
            help='download file from server')
    parser.add_argument('-r', '--recursive', action='store_true',
            help='recursive')
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
    #  user_config_path = config_dir / Path(args.user+'.ini')
    user_config_path = config_dir / Path('settings.ini')
    config = configparser.ConfigParser()
    if os.path.exists(user_config_path):
        config.read(user_config_path)
    if args.generate or args.user not in config.sections():
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
                print("%s doesn't have correspond otp key"%(args.user))
                exit(1)

        config[args.user] = {
                "otp_key": otp_key
                }
        update_password(args, config, user_config_path, logger)

    #  else:
        #  if args.generate or args.user not in config.sections():
            #  update_password(args, config, user_config_path, logger)

    #  else:
        #  print('Exist!')
    return config

def update_password(args, config, user_config_path, logger=None):
    args.update = True
    #  user = getpass.getuser() 
    pss = getpass.getpass("Username: %s\nPassword:"%(args.user)) 
    key, token = encrypt_password(pss)
    config[args.user]['key'] = key
    config[args.user]['token'] = token
    with open(user_config_path, 'w') as f:
        config.write(f)
def get_file_abs_path(path):
    cwd = Path(os.getcwd())
    if str(path)[0] != '/':
        path = cwd / path
    return path


if __name__ == '__main__':
    args = _parse_args()
    script_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    print('script_dir:',script_dir)
    args.update = False
    config = check_config(args, script_dir)
    pss = decrypt_password(config[args.user]['key'], config[args.user]['token'])
    if args.pss and not args.update:
        user = getpass.getuser()
        pss = getpass.getpass("Username: %s\nFill in your password manually:"%(args.user)) 
    otp_code = pyotp.TOTP(config[args.user]['otp_key'])
    pssOtp = pss + otp_code.now().strip()
    #  print("pssOtp:", pssOtp)
    if not args.upload and not args.download:
        os.system("sshpass -p \"%s\" ssh %s@ln01.twcc.ai"%(pssOtp, args.user))
    if (args.local is None or args.server is None) and (args.upload or args.download):
        print("src or target is None!")
        exit(1)
    cwd = Path(os.getcwd())
    if args.local is not None:
        local = get_file_abs_path(args.local)
    #  args.server = args.server.strip()
    print("server path:%s local path:%s"%(args.server, local))
    #  if args.tgt is not None:
        #  tgt = get_file_abs_path(args.tgt)
    if args.upload and args.download:
        print("Can't upload and download at the same time!")
    if args.download:
        if args.recursive:
            os.system("sshpass -p \"%s\" scp -r %s@ln01.twcc.ai:%s %s"%(pssOtp, args.user, args.server, local))
        else:
            os.system("sshpass -p \"%s\" scp  %s@ln01.twcc.ai:%s %s"%(pssOtp, args.user, args.server, local))
    elif args.upload:
        if args.recursive:
            os.system("sshpass -p \"%s\" scp -r %s %s@ln01.twcc.ai:%s "%(pssOtp, local, args.user, args.server))
        else:
            os.system("sshpass -p \"%s\" scp %s %s@ln01.twcc.ai:%s"%(pssOtp, local, args.user, args.server))

    #  print('password =', pss)

#  otp_code = pyotp.TOTP(otp_key)

#  user = getpass.getuser() 
#  pss = getpass.getpass("Username: %s\nPassword:"%(user)) 

#  pssOtp = pss + otp_code.now().strip()

