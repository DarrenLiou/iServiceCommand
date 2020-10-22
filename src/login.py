import pyotp
import getpass
import os
import argparse
import configparser
from pathlib import Path, PurePath

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
    parser.add_argument('--safe', action='store_true',
            help='Set this flag to use the setuid() feature with safety, which is experimental')
    args = parser.parse_args()
    return args
def check_config(args, script_dir, logger=None):
    config_dir = PurePath(script_dir / '../config')
    print('config_dir:', config_dir)
    if not os.path.exists(config_dir):
        print('Create config directory')
        os.makedirs(config_dir)
    #  else:
        #  print('Exist!')
    return config_dir



if __name__ == '__main__':
    args = _parse_args()
    script_dir = Path(os.path.dirname(os.path.realpath(__file__)))
    print('script_dir:',script_dir)
    check_config(args, script_dir)
    
#  otp_key = "Q47THR6X4A6RQE5SWBL3YXD4N27G7NOP65SNGP36DBKZ7R5HMBMA===="
#  otp_code = pyotp.TOTP(otp_key)

#  user = getpass.getuser() 
#  pss = getpass.getpass("Username: %s\nPassword:"%(user)) 

#  pssOtp = pss + otp_code.now().strip()

#  os.system("sshpass -p \"%s\" ssh darren1629@ln01.twcc.ai"%(pssOtp))
