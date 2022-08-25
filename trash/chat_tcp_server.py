#!/bin/python3
import socket
import sys
import argparse
import socketserver as SocketServer
import threading
import signal

import pickle as cPickle
import struct
import select


host0 = '172.17.0.1'
SERVER_HOST = 'localhost'
SERVER_HOST = host0
data_payload = 2048
backlog = 5

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
	
	
class TCPChatServer(object):
	"""An example of chat server using select
	"""
	def __init__(self, port, backlog=5):
		self.clients = 0
		self.clientmap = {}
		#List output sockets
		self.outputs = [] 
		self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#Enable reusing socket address
		self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.server.bind((SERVER_HOST, port))
		print("Listening to port " + str(port) + "...")
		self.server.listen(backlog)
		#Catch keyboardInterrupts
		signal.signal(signal.SIGINT, self.sigHandler)
		
	def sigHandler(self, signum, frame):
		""" Clean up client outputs
		"""
		#CLose the server
		print("\nShutting down the server...")
		#close exixting sockets
		for output in self.outputs:
			output.close()
		self.server.close()
		sys.exit(1)
	def get_client_name(self, client):
		"""Return the name of the client
		"""
		info = self.clientmap[client]
		host,name= info[0][0], info[1]
		return '@'.join((name, host))
		
	def run(self):
		inputs = [self.server, sys.stdin]
		self.outputs =[]
		running = True
		while running:
			try:
				readable, writable, exceptional = select.select(inputs, self.outputs, [])
			except select.error as e:
				print("Error running select module, Exception: %s" %str(e))
				break
			except Exception as e:
				print("Select method failed, Exception: %s" %str(e))
				break
			for sock in readable:
				if sock == sys.stdin:
					#handle standard inputs
					junk = sys.stdin.readline()
					running = False
				elif sock == self.server:
					#Handle the server socket
					client, address = self.server.accept()
					print("Chat server: got connexion %d from %s" %(client.fileno(), address))
					#Read Login name
					try:
						cname = receive(client).split('NAME: ')[1]	
					except Exception as e:
						print("receive failed, connexion may have been lost. Exception: %s"%str(e))	
						break
					#compute client name and send back
					self.clients += 1
					send(client, 'CLIENT: ' + str(address[0]))
					inputs.append(client)
					self.clientmap[client] = (address, cname)
					#send joining information to other clients
					msg = "\nConnected: New client (%d) from %s" %(self.clients, self.get_client_name)
					for output in self.outputs:
						send(output, msg)
					self.outputs.append(client)
				else:
					#Handle all other sockets
					try:
						data = receive(sock)						
						if data: 
							# Send as new client's message
							msg = '\n#[' + self.get_client_name(sock) + ']>>' + data
							for output in self.outputs:
								if output != sock:
									send(output, msg)
									print(msg)
								#send(output, '[ACK]')
						else:
							print("Chat server: %d hung up" %sock.fileno())
							self.clients -= 1
							sock.close()
							inputs.remove(sock)
							self.outputs.remove(sock)
							#Sending client leaving infos to others
							msg = "\n(Now hung up: Client from %s)" %self.get_client_name(sock)
							for output in self.outputs:
								send(output, msg)	
					except Exception as e:
						print("\nSocket error occured, Exception: %s" %str(e))
						inputs.remove(sock)
						self.outputs.remove(sock)
		self.server.close()
				

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Socket Server Example with select')
	parser.add_argument('-n','--name', action = "store", dest = "name", required = True)
	parser.add_argument('-p', '--port', action = "store", dest = "port", type = int, required = True)
	given_args = parser.parse_args()
	port = given_args.port
	name = given_args.name
	server = TCPChatServer(port)
	server.run()
	
	
