#!/bin/python3
import socket
import sys
import argparse
import socketserver as SocketServer
import threading
from binascii import hexlify

host0 = '172.17.0.1'
host = 'localhost'
data_payload = 2048
backlog = 5

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
	def handle(self):
		data = self.request.recv(data_payload)
		current_thread = threading.current_thread()
		response = "%s %s" %(current_thread.name, data)
		self.request.sendall(str.encode(response))

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
	"""Nothing to add here, inherited everything necessary from parents
	"""
	pass

def echo_server(port):
	#create a TCP socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Enable reuse address/port
	s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	#bind the socket to the port
	server_address = (host, port)
	print ("Starting up echo server on %s port %s" % server_address)
	s.bind(server_address)
	s.listen(backlog)
	while True:
		print ("Waiting for messages from the client")
		client, address = s.accept()
		data = str.encode("Hello world")
		if data:
			print ("Data: %s" %data)
			client.send(data)
			print ("Send %s bytes back to %s" %(data, address))
		client.close()

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Socket Server Example')
	parser.add_argument('--port', action = "store", dest = "port", type = int, required = True)
	given_args = parser.parse_args()
	port = given_args.port
	#echo_server(port)
	server = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
	#retrieve ip address
	ip, port = server.server_address
	print("Server ip: %s\nListening port: %s" %(ip, port))
	#Create a thread with the server
	server_thread = threading.Thread(target=server.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	#cleanup the server
	print("waiting for incomming connexion")
	try:
		while(1): pass
	except KeyboardInterrupt:
		print("\nShutting down the server")		
		server.shutdown()
		print("[done]")
	
	
