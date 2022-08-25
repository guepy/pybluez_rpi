#!/bin/python3
import socket
import sys
import argparse

host = 'localhost'

def echo_client(port):
	#create a TCP socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# connect the socket to the server
	server_address = (host, port)
	print ("Connecting to %s, port %s" % server_address)
	try:
		s.connect(server_address)
	except Exception as e:
		print ("Connexion failed, Exception: %s" %str(e))
		sys.exit(1)
	
	#Send data
	try:
		msg = str.encode("Test message. This will be echoed")
		print ("Sending %s" %msg)
		s.sendall(msg)
		#Look for the response
		amount_received = 0
		amount_expected = len(msg)
		while amount_received < amount_expected:
			data = s.recv(120)
			amount_received += len(data)
			print ("Received: %s" %data)
	except Exception as e:
		print ("Exception: %s" %str(e))
	finally:
		print ("Closing connection to the server")
		s.close()
		
		

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'Socket Client Example')
	parser.add_argument('--port', action = "store", dest = "port", type = int, required = True)
	given_args = parser.parse_args()
	port = given_args.port
	echo_client(port)
	
