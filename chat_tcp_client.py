#!/usr/bin/env python
import socket
import sys
import argparse
import pickle as cPickle
import struct
import select
from binascii import hexlify

HOSTNAME = 'localhost'

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
	except struct.error as e:
		return ''
	buf = ""
	while len(buf) < size:
		buf = channel.recv(size - len(buf))
	
	return cPickle.loads(buf)[0]
	
	
class TCPChatClient(object):
	"""AA chat client using select"""
	def __init__(self, name, port, host = HOSTNAME):
		self.name = name
		self.connected = False
		self.host = host
		self.port = port
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
			#received data contains the client address, set it
			addr = data.split('CLIENT: ')[1]
			self.prompt = '[' + '@'.join((self.name, addr)) + ']'
			
		except socket.error as e:
			print("Failed to connect to the server %s @ port %d" %(host, port))
			
	def run(self):
		"""chat cleint main loop
		"""
		while self.connected:
			try:
				sys.stdout.write(self.prompt)
				sys.stdout.flush()
				#wait for input from socket or stdin
				readable, writable, exceptional = select.select([sys.stdin,self.sock], [], [])
				for sock in readable:
					if sock == sys.stdin:
						data = sys.stdin.readline().strip()
						if data: send(self.sock, data)
					elif sock == self.sock:
						data = receive(sock)
						if not data:
							print("Client shutting down")
							self.connected = False
							break
						else:
							sys.stdout.write(data + '\n')
							sys.stdout.flush()
			except KeyboardInterrupt:
				print("\nClient interrupt")
				self.sock.close()
				break
				

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Socket Server Example with select')
	parser.add_argument('-n','--name', action = "store", dest = "name", required = True)
	parser.add_argument('-p', '--port', action = "store", dest = "port", type = int, required = True)
	given_args = parser.parse_args()
	port = given_args.port
	name = given_args.name
	client = TCPChatClient(name, port)
	client.run()
	
	
