#!/usr/bin/env python
import socket
import sys
import argparse
import pickle as cPickle
import struct
import select
from binascii import hexlify
import threading

HOSTNAME = '172.17.0.1'

#utilities
def send(channel, *args):
	buf = cPickle.dumps(args)
	value = socket.htonl(len(buf))
	size = struct.pack("L", value)
	channel.send(size)
	channel.send(buf)
	
def receive(channel):
	size = struct.calcsize("L")
	size = channel.recv(size)
	try:
		size = socket.ntohl(struct.unpack("L", size)[0])
		if size > sys.maxsize:
			return ""
	except struct.error as e:
		print('socket.ntohl failed, Exception: %s' %str(e))
		return ''
	except Exception as e:
		print('receive failed, Exception: %s' %str(e))
		return ''
	buf = ""
	buf_len = len(buf)
	while buf_len < size:
		buf = channel.recv(size - buf_len)
		buf_len = len(buf)
	
	return cPickle.loads(buf)[0]
	
	
class TCPChatClient(object):
	"""A chat client using select"""
	def __init__(self, name, port, host = HOSTNAME):
		self.name = name
		self.connected = False
		self.host = host
		self.port = port
		self.msg_payload = ''
		#initial prompt
		self.prompt = '[' + '@'.join((name, socket.gethostname().split('.')[0])) + ']'
		#connect to server
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((host,self.port))
			print("Now connected to server %s @ port %d" %(host, self.port))
			self.connected = True
			#send client name
			send(self.sock, 'NAME: '+self.name)
			data = receive(self.sock)
			
		except socket.error as e:
			print("Failed to connect to the server %s @ port %d" %(host, port))
			
		try:
			#received data contains the client address, set it
			print("data received: %s" %data)
			addr = data.split('CLIENT: ')[1]
			self.prompt = '[' + '@'.join((self.name, addr)) + ']'
		except Exception as e:
			print("The received msg does not match the expected format")
			
	def run(self):
		"""
		chat cleint main loop
		"""
		while self.connected:
			try:
				sys.stdout.write(self.prompt)
				sys.stdout.flush()
				#wait for input from socket or stdin
				readable, writable, exceptional = select.select([sys.stdin, self.sock], [], [])
				for sock in readable:
					if sock == self.sock:
						data = receive(sock)
						if not data:
							print("Client shutting down")
							self.connected = False
							break
						else:
							sys.stdout.write(data + '\n')
							sys.stdout.flush()
							
					elif sock == sys.stdin:
						data = sys.stdin.readline().strip()
						if data: send(self.sock, data)
					else:
						print("unknow file descriptor")
			except KeyboardInterrupt:
				print("\nClient interrupt")
				#self.sock.close()
				break
			except Exception as e:
				print("Exception occured in run: %s" %str(e))
				#self.sock.close()
				break
	def send_msg(self,msg):
		if self.connected:
			send(self.sock, msg)
			try:
				readable, writable, exceptional = select.select([self.sock], [], [], 1)
				for sock in readable:
					if sock == self.sock:
						try:
							data = receive(sock)
							if not data:
								print("server did not acknowledge the message")
							elif data == '[ACK]':
								print('[message sent]')
							else:
								print('unknow msg status')
						except Exception as e:
							print("Connexion down, Exception: %s" %str(e))
							
					else:					
						print("Did not get any response from the server within 10 secs. Server might be down")				
			except Exception as e:
				print("Exception occured in send_msg: %s" %str(e))
				#self.sock.close()
		else:
			print("Can not send msg: The client is not connected to the server")
	def clear(self):
		print("Clear: Client shutting down")
		self.sock.close()
		self.connected = False
						

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Socket Server Example with select')
	parser.add_argument('-n','--name', action = "store", dest = "name", required = True)
	parser.add_argument('-p', '--port', action = "store", dest = "port", type = int, required = True)
	given_args = parser.parse_args()
	port = given_args.port
	name = given_args.name
	client = TCPChatClient(name, port)
	client.run()
	
	
