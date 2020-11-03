# iServiceCommand
Auto connect to iService with "ssh" and "scp" command. 


## Intro
For the safety, we need to generate otp code and append to our password to login iService every time. However, it is quite annoying and sometimes leads to connection failed under high latency or low bandwith of the Internet.
Thus, we try to write a script to auto login iService with 'ssh' and 'scp' features. Moreover, to avoid hard-coding our passwords into the scripts, we encrypt the password user types at the first time and store it. Then, user can automatically login to the server without typing again.

## Requirements

```
pip install cryptography
pip install pyotp
sudo apt-get install sshpass
```
Note: If a new user first login to  iService with this script, you need to copy the otp key to ```config/otp.json``` with the format of following:
```
{
  "username":"otpcode"
}
```

## Usage

To read the help message:
```
python login.py  -h
```

To login:
```
python login.py --user [username]
```

To upload files to server:
```
python login.py --user [username] -u -l [path of files in local] -s [path of files in server]
```

To download files to server:
```
python login.py --user [username] -d -l [path of files in local] -s [path of files in server]
```

You can specify ```-r``` argument if you want to scp a directory.
