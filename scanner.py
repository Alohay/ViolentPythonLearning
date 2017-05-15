# 脚本没有跑过 仅作为练习

# -*- coding:utf-8 -*-

# import optparse #python3中改用argparse

# parser = optparse.OptionParser('usage %prog -H <target Host> -p <target Port')
# parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
# parser.add_option('-P', dest='tgtPort', type='int', help='specify target port')

# (options, args) = parser.parse_args()
# tgtHost = options.tgtHost
# tgtPort = options.tgtPort

# if (tgtHost == None or tgtPort == None):
# 	print(parser.usage)
# 	exit(0)
# else:
# 	print (tgtHost)
# 	print (tgtPort)

import optparse, socket, threading


screenLock = threading.Semaphore(value=1)
def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connSkt.connect(tgtHost, tgtPort)
		connSkt.send('violentPython\r\n')
		res = connSkt.recv(100)
		screenLock.acquire()
		print('\n[+]%d/tcp open' % tgtPort)
		print('[+] ' + str(res))
		connSkt.close()
	except:
		screenLock.acquire()
		print('[-]%d/tcp closed' % tgtPort)
	finally:
		screenLock.release()
		connSkt.close()

def portScan(tgtHost, tgtPorts):
	try:
		tgtIp = socket.gethostbyname(tgtHost)
	except:
		print("[-]Cannot resolve '%s': Unknown host" % tgtHost)
		return

	try:
		tgtName = socket.gethostbyaddr(tgtIp)
		print('\n[+] Scan Result for : ' + tgtName[0])
	except:
		print('\n[+] Scan Result for : ' + tgtIp)

	socket.setdefaulttimeout(1) # 1s

	for tgtPort in tgtPorts:
		print('\nScanning port ' + str(tgtPort))
		t = threading.Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
		# connScan(tgtHost, int(tgtPort))

def main():
	parser = optparse.OptionParser('usage %prog -H <target host> -P <target port>')
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-P', dest='tgtPort', type='int', help='specify target port')
	(options, args) = parser.parse_args()

	# 输入为-H 127.0.0.1 -P 21 23 445 80
	# print(str(options)) # {'tgtHost': '127.0.0.1', 'tgtPort': 21}
	# print(str(args)) # ['23', '445', '80'] 
	tgtHost = options.tgtHost
	tgtPort = options.tgtPort
	args.append(tgtPort)

	if (tgtHost == None) or (tgtPort == None):
		print('[-] You must specify a target host and posts!')
		exit(0)

	portScan(tgtHost, args)

if __name__ == '__main__':
	main()


