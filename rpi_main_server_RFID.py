#!/usr/bin/python3

from gi.repository import GLib
import dbus
import os
import sys
import socket
import bluetooth_utils as btu
import btc
import dbus.service
import dbus.mainloop.glib as dmg
import eccel_tag_param as etp
import eccel_utils as ecu
import sensortile_ble_constants as sbc
import ctypes
import csv
import struct
from datetime import datetime
import concurrent.futures as cf
import threading
from threading import Thread, Event
from queue import Queue
import argparse
import signal
import json
import pickle as cPickle
import select
from binascii import hexlify
import time
import math
import yaml
from yaml import SafeLoader

sys.path.insert(0,'.')
# define the bluetooth controler
adapter_interface = None
adapter_path = None
adapter_proxy = None
device_interface = None

MAX_BLCK_CNT_PER_READ = 2
MAX_BLCK_CNT_PER_WRITE = MAX_BLCK_CNT_PER_READ 
mainLoop = None
timer_id = None
managed_objects_nbr = 0
found_src = False
found_chr = False
src_path_list = []
chr_path_list = []
desc_path_list = []
EXIT_APP = False
managed_objects = None
src_resolved_ok = False
quat_read_id = 0
quat_time_tag =0
reboot_ctr =0
MAX_FAILLURE = 6
rot_hex_x = 0
rot_hex_y = ''
rot_hex_z = ''
accLin_hex_x = ''
accLin_hex_y = ''
colision_ctr = -1
tcp_rx_queue = Queue()
tcp_tx_queue = Queue()
ble_queue = Queue()
tcp_rx_evt = Event()
#tcp_tx_evt = Event()
ble_evt = Event()
tcp_rx_evt.clear()
ble_evt.clear()

ECCEL_READER_BDADDR1='24:6F:28:1A:61:8A'
ECCEL_READER_BDADDR2='8C:AA:B5:80:19:D2'
ECCEL_READER_PATH = ""
ECCEL_reader_name = ''

msg = {
"name": "",
"topic":"" ,
"payload":"" 
}

BTADDR_OF_INTEREST= ECCEL_READER_BDADDR2

HOSTNAME = '172.17.0.1'
TCP_HOSTNAME = '172.17.0.1'
TCP_PORT = 3355

DEBUG_ON = 1
#declare a list of path
path_list = []

#declare a dictionary of device with the scheme [device, properties]
devices = {}
ECCEL_send_cmd_path = ''
ECCEL_read_path = ''
SENSORTILE_env_sensors_read_path = ''
SENSORTILE_motion_sensors_read_path = ''
SENSORTILE_quaternions_read_path = ''
connexion_ok = False
	
#these service routines argument will be served by signal they are bound to as they
#are follow the signal-slot mechanism
def Interfaces_added(path, interfaces):
	#interface is an array of dictionnary
	global devices
	global found_src
	global found_chr
	global src_path_list 
	global chr_path_list
	global desc_path_list
	global ECCEL_read_path
	global ECCEL_READER_PATH
	global ECCEL_connected
	global ECCEL_send_cmd_path
	global DEBUG_ON
	global client 
	global bus
	global dev_chr_proxy_write_eccel
	global dev_chr_interface_write_eccel
	print("Interface added")

	if btc.DEVICE_INTERFACE in interfaces:
		device_properties = interfaces[btc.DEVICE_INTERFACE]
		if path not in devices:
			
			msg["name"] = "INTERFACE ADDED"
			print("New device: {}".format(path))
			#New dictionnary entry
			devices[path] = device_properties
			dev = device_properties
			path_list.append(path)
			if 'Name' in dev:
				print("Device Name: {}".format(dev['Name']))				
				msg["topic"] = str(dev['Name'])
				
			if 'Address' in dev:
				add = dev['Address']
				msg["payload"] = str(add)
				print("Device address: {}".format(add))
				if add == BTADDR_OF_INTEREST:
					print("ECCEL Reader added")
					ECCEL_READER_PATH = path
			if 'RSSI' in dev:
				print("Device RSSI: {}".format(dev['RSSI']))
			print("-----------------------------------------------------------")
		
	if btc.GATT_SERVICE_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_SERVICE_INTERFACE]
		print("Service Path: {}".format(path))
		src_path_list.append(path)
		msg["name"] = "SVC_ADDED"
		msg["topic"] = str(path)
		if 'UUID' in prop:
			uuid = prop['UUID']
			msg["payload"] 	= str(uuid)
			print("Service UUID: {}".format(btu.dbus_to_python(uuid)))			
			print("Service Name: {}".format(btu.get_name_from_uuid(uuid)))
			if btc.DEVICE_INF_SVC_UUID == uuid:
				found_src = True
				src_path = path
		print("-----------------------------------------------------------")
		
	if btc.GATT_CHARACTERISTIC_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_CHARACTERISTIC_INTERFACE]
		print("Charractetitic Path: {}".format(path))
		chr_path_list.append(path)
		msg["name"] = "CHAR_ADDED"
		msg["topic"] = str(path)
		if 'UUID' in prop:
			uuid = btu.dbus_to_python(prop['UUID'])
			msg["payload"] 	= uuid
			print("Charractetitic UUID: {}".format(uuid))			
			print("Charractetitic Name: {}".format(btu.get_name_from_uuid(prop['UUID'])))
				
			if btc.ECCEL_READ_CHARACTERISTIC_UUID == uuid:
				Start_characteristic_notification(path)
				ECCEL_read_path = path
			if btc.ECCEL_WRITE_CHARACTERISTIC_UUID == uuid:
				ECCEL_send_cmd_path = path
				dev_chr_proxy_write_eccel = bus.get_object(	btc.BLUEZ_SERVICE_NAME, path)
				dev_chr_interface_write_eccel = dbus.Interface(dev_chr_proxy_write_eccel, btc.GATT_CHARACTERISTIC_INTERFACE)
		flags = ''
		for f in prop['Flags']:
			flags = flags + f + ','
		print("Charractetitic Flags: {}".format(btu.dbus_to_python(flags)))	
		print("-----------------------------------------------------------")
		
	if btc.GATT_DESCRIPTOR_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_DESCRIPTOR_INTERFACE]
		msg["name"] = "DESC_ADDED"
		msg["topic"] = str(path)
		print("-----------------------------------------------------------")
		print("Descriptor Path: {}".format(path))
		desc_path_list.append(path)
		if 'Name' in prop:	
			print("Descriptor Name: {}".format(btu.get_name_from_uuid(prop['Name'])))
			msg["payload"] 	= str(prop['Name'])
		if 'UUID' in prop:
			print("Descriptor UUID: {}".format(btu.dbus_to_python(prop['UUID'])))	
			msg["payload"] 	= str(prop['UUID'])
		#Read_descriptor_value(path)	
		
	return

def free_buf_after_send(msg):
	msg["name"] = ""
	msg["topic"] = ""
	msg["payload"] = ""
	
def Start_characteristic_notification(chr_path):
	global bus
	global ECCEL_read_path
	
	dev_chr_proxy = bus.get_object(	btc.BLUEZ_SERVICE_NAME, chr_path)
	dev_chr_interface = dbus.Interface(dev_chr_proxy, btc.GATT_CHARACTERISTIC_INTERFACE)
	bus.add_signal_receiver(Char_notification_received, dbus_interface = btc.DBUS_PROPERTIES,
		signal_name = "PropertiesChanged", path = chr_path, path_keyword = "path")

	'''
	notification_string = ''
	if chr_path == ECCEL_read_path:
		notification_string = 'ECCEL RFID Reader Card'
	'''
	try:
		dev_chr_interface.StartNotify()
	except Exception as e:
		print('failed to register notifications on  {}'.format(chr_path))
		print(e.get_dbus_name())
		print(e.get_dbus_message())
		return btc.RESULT_EXCEPTION
	else:
		print('successfully register to notifications on {}'.format(chr_path))
		return btc.RESULT_OK

def Char_notification_received(interface, changed, not_used, path):
	global bus
	global ble_queue
	global ble_evt
	global ECCEL_read_path
	global ECCEL_BLE_EVT
	
	print("Char notification received")
	if 'Value' in changed:
		if path == ECCEL_read_path:
			text = btu.dbus_to_python(changed['Value'])
			ble_queue.put((ECCEL_BLE_EVT, text))
		ble_evt.set()
		return btc.RESULT_OK
			
def Read_characteristic_value(chr_path):
	global bus
	dev_chr_proxy = bus.get_object(	btc.BLUEZ_SERVICE_NAME, chr_path)
	dev_chr_interface = dbus.Interface(dev_chr_proxy, btc.GATT_CHARACTERISTIC_INTERFACE)
	try:
		val = dev_chr_interface.ReadValue({})
	except Exception as e:
		print('failed to read characteristic {}'.format(chr_path))
		print(e.get_dbus_name())
		print(e.get_dbus_message())
		return btc.RESULT_EXCEPTION
	else:
		tmp = btu.dbus_to_python(val)
		print('char: {} \n Value : {}'.format(chr_path, tmp))
		return btc.RESULT_OK
		
def Send_ECCEL_cmd(cmd, arg):
	global ECCEL_send_cmd_path
	'''
	Before sending any commands to the eccel reader we need to disable polling
	as the reader can not poll and answer to request simultaneously
	'''
	if ECCEL_send_cmd_path != '':
		#reset_polling()		
		to_send = ecu.Format_ECCEL_cmd(cmd, arg)
		Write_characteristic_value(ECCEL_send_cmd_path, to_send)
		#set_polling()
	else:
		print('unknow char path')
	
def Read_descriptor_value(chr_path):
	global bus
	dev_chr_proxy = bus.get_object(	btc.BLUEZ_SERVICE_NAME, chr_path)
	dev_chr_interface = dbus.Interface(dev_chr_proxy, btc.GATT_DESCRIPTOR_INTERFACE)
	try:
		val = dev_chr_interface.ReadValue({})
	except Exception as e:
		print('failed to read descriptor {}'.format(chr_path))
		print(e.get_dbus_name())
		print(e.get_dbus_message())
		return btc.RESULT_EXCEPTION
	else:
		tmp = btu.dbus_to_python(val)
		print('Desc: {} \n Value : {}'.format(chr_path, tmp))
		return btc.RESULT_OK
		
	
def Write_characteristic_value(chr_path, value):
	global dev_chr_interface_write_eccel
	try:
		#text = btu.text_to_ascii_array(value)
		dev_chr_interface_write_eccel.WriteValue(value, {})
	except Exception as e:
		print('failed to write characteristic {}'.format(chr_path))
		print(e.get_dbus_name())
		print(e.get_dbus_message())
		return btc.RESULT_EXCEPTION
	else:
		
		print('write to {} suceeed'.format(chr_path))
		return btc.RESULT_OK
			


def Discover_dev(timeout):
	global adapter_interface
	global adapter_path
	global mainLoop
	global timer_id
	global bus
	adapter_path = btc.BLUEZ_NAMESPACE + btc.ADAPTER_NAME
	#Acquire an adapter proxy object and its Adapter1 interface so that we can call its methods
	adapter_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME, adapter_path)
	adapter_interface = dbus.Interface(adapter_proxy, btc.ADAPTER_INTERFACE)
	
	#Register signal_handler so we can asynchronously reprted new device discovered
	#Remember the InterfaceAdded signal is sent each time the adapter receive a discovery 
	#packet from a device unknow by its device list
	bus.add_signal_receiver(Interfaces_added, dbus_interface = btc.DBUS_OM_IFACE,
		signal_name = "InterfacesAdded")
	bus.add_signal_receiver(Interfaces_removed, dbus_interface = btc.DBUS_OM_IFACE,
		signal_name = "InterfacesRemoved")
	bus.add_signal_receiver(Properties_changed, dbus_interface = btc.DBUS_PROPERTIES,
		signal_name = "PropertiesChanged", path_keyword = "path")
	mainLoop = GLib.MainLoop()
	timer_id = GLib.timeout_add(timeout, Discovery_timeout)
	adapter_interface.StartDiscovery(byte_arrays = True)
	#Disconnect_dev(BTADDR_OF_INTEREST)	
	for path in path_list:
		dev_dict = devices[path]
		Disconnect_dev(dev_dict)
		Remove_dev(dev_dict)
	mainLoop.run()

def Discovery_timeout():
	global timer_id
	global bus
	global adapter_interface
	global mainLoop
	global devices
	global tcp_rx_evt
	global tcp_rx_queue
	global ECCEL_connected
	
	#GLib.source_remove(timer_id)
	#mainLoop.quit()
	#adapter_interface.StopDiscovery()
	#bus.remove_signal_receiver(Interfaces_added, "InterfacesAdded")
	#bus.remove_signal_receiver(Interfaces_removed, "InterfacesRemoved")
	#bus.remove_signal_receiver(Properties_changed, "PropertiesChanged")
	List_dev_found()
	for path in path_list:
		dev_dict = devices[path]
		if dev_dict['Address'] == BTADDR_OF_INTEREST:
			Connect_dev(dev_dict)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_ICODE_INVENTORY_NEXT.value,[])
	print("\nreadall is %d"%ecu.readall)
	if ecu.readall == 1:
		#This is excuted every 1 min according to the reader settings
		#Send_ECCEL_cmd(etp.CMD_LIST.CMD_ACTIVATE_TAG.value,[])
		msg = {
			"name":"ECCEL_READER",
			"topic": "READ_ALL",
			"payload":""
				}

		ecu.readall = 0
	else:
		msg = {
			"name":"ECCEL_READER",
			"topic": "TAG_INVENTORY_NEXT",
			"payload":""
				}
	tcp_rx_queue.put(msg)
	tcp_rx_evt.set()
	if ECCEL_connected == False:
		print("RFID Reader bluetooth is not active")
	return True

def Interfaces_removed(path, interfaces):
	global devices
	global ECCEL_connected
	if not btc.DEVICE_INTERFACE in interfaces:
		return
	if path in devices:
		dev = devices[path]
		if dev == ECCEL_READER_PATH:
			print("ECCEL Reader removed")			
			ECCEL_connected = False
		if 'Address' in dev:
			print("Deleting device\'s address {}...".format(btu.dbus_to_python(dev['Address'])))
		else :
			print("Deleting path {}...".format(path))	
		del devices[path]
		if path in path_list:
			path_list.remove(path)
		print("-----------------------------------------------------------")


#Can be used to snife device position
def Properties_changed(interface, changed, not_used, path):
	global devices
	global src_resolved_ok
	global client
	
	
	if interface == btc.DEVICE_INTERFACE:
		if path in devices:
			devices[path] = dict(devices[path].items())
			devices[path].update(changed.items())
		else:
			devices[path] = changed	
		
		dev = devices[path]
		n_s = 0
		print("Properties changed\nPath: {}".format(path))
		if 'Name' in dev:
			print("Device Name: {}".format(btu.dbus_to_python(dev['Name'])))
			n_s += 1
		if 'Address' in dev:
			print("Device Address: {}".format(btu.dbus_to_python(dev['Address'])))
		if 'RSSI' in dev:
			print("Device RSSI: {}".format(btu.dbus_to_python(dev['RSSI'])))
			
		if 'ServicesResolved' in changed:
			src_resolved_ok = btu.dbus_to_python(changed['ServicesResolved'])
			print("ServicesResolved: {}".format(src_resolved_ok))
			n_s += 1
			
		print("-----------------------------------------------------------")
		if n_s == 2:
			if path == ECCEL_READER_PATH:
				if src_resolved_ok:					
					Send_ECCEL_cmd(etp.CMD_LIST.CMD_ICODE_INVENTORY_START.value,[])
					#Send_ECCEL_cmd(etp.CMD_LIST.CMD_GET_TAG_COUNT.value,[])
					#Send_ECCEL_cmd(etp.CMD_LIST.CMD_GET_UID.value,[1])
					#set_polling()
					pass
		

def Get_known_dev():
	global managed_objects_nbr
	global bus
	global devices
	global managed_objects
	global path_list
	global object_manager
	object_manager = dbus.Interface(bus.get_object(btc.BLUEZ_SERVICE_NAME, "/"), btc.DBUS_OM_IFACE)
	managed_objects = object_manager.GetManagedObjects()
	 
	
	print("---- Existing paths ---")
	for path, ifaces in managed_objects.items():
		for iface_name in ifaces:
			if iface_name == btc.DEVICE_INTERFACE:
				managed_objects_nbr += 1
				print("Path {}: {}".format(managed_objects_nbr, path))
				device_properties = ifaces[btc.DEVICE_INTERFACE]
				devices[path] = device_properties
				path_list.append(path)
				if 'Address' in device_properties:
					print('Address: {}'.format(device_properties['Address']))
					print("-----------------------------------------------------")
	
def List_dev_found():
	global devices
	print("**********************************************************************")		
	print("List of known devices")
	print("**********************************************************************")	
	ctr = 1
	for path in devices:
		dev =devices[path]
		if 'Address' in dev:
			if 'Name' in dev:
				print("{}) Name: {}, Address: {}".format(ctr, 
				btu.dbus_to_python(dev['Name']),btu.dbus_to_python(dev['Address'])))
			else:
				print("{}) Unknow name, Address: {}".format(ctr, 
				btu.dbus_to_python(dev['Address'])))
			
		ctr += 1

def set_polling():
	print("Setting polling...")	
	cmd = ecu.Format_ECCEL_cmd(etp.CMD_LIST.CMD_SET_POLLING.value, [1])
	Write_characteristic_value(ECCEL_send_cmd_path, cmd)
	

def reset_polling():
	print("Resetting polling...")	
	cmd = ecu.Format_ECCEL_cmd(etp.CMD_LIST.CMD_SET_POLLING.value, [0])
	Write_characteristic_value(ECCEL_send_cmd_path, cmd)
		
def reboot_BLE_rfid_reader():
	print("Rebooting RFID_READER...")
	msgs={
		"name":ECCEL_reader_name,
		"topic":"CONNEXION",
		"payload":"Rebooting"
		}
	tcp_tx_queue.put(msgs)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_REBOOT.value,[])
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_PROTO_CONF.value, [etp.SUBCMD_LIST.SUBCMD_BLUETOOTH_ID.value ,etp.BLUETOOTH_SETTINGS.BLE.value])
	
def Connect_dev(dev_prop_dict):
	global bus
	global devices
	global adapter_path
	global client
	global tcp_tx_queue
	global ECCEL_connected
	global ECCEL_reader_name
	global reboot_ctr
	global MAX_FAILLURE
	
	dev_add = dev_prop_dict['Address']
	if 'Name' in dev_prop_dict:		
		try:
			device_path = btu.device_address_to_path(dev_add, adapter_path)
			device_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME,device_path)
			device_interface = dbus.Interface(device_proxy, btc.DEVICE_INTERFACE)
			ECCEL_reader_name = str(btu.dbus_to_python(dev_prop_dict['Name']))
			if(Is_dev_connected(device_proxy) == True):
				print("Device {} is already connected".format(ECCEL_reader_name))
				return
			else:
				print("-----------------------------------------------------")
				print("Connecting to {}...".format(dev_add))
				device_interface.Connect()
		except Exception as e:
			ECCEL_connected = False
			print("Connexion failed")
			
			msg={
				"name":ECCEL_reader_name,
				"topic":"CONNEXION",
				"payload":"FAILED"
				}
			reboot_ctr += 1
			if reboot_ctr >= MAX_FAILLURE:
				reboot_BLE_rfid_reader()
				reboot_ctr = 0
			tcp_tx_queue.put(msg)
			e_name = e.get_dbus_name()
			print(e_name)
			print(e.get_dbus_message())
			if("UnknowObject" in e_name):
				print("The device may not be in the reach of the adapter")
			return btc.RESULT_EXCEPTION
		else:
			print("Connexion succeed")
			msgs={
				"name":ECCEL_reader_name,
				"topic":"CONNEXION",
				"payload":"SUCCESS"
				}
			ECCEL_connected = True
			tcp_tx_queue.put(msgs)
			return btc.RESULT_OK
	else:
		print("WARNING!! Skiping connexion to {} as I think it is not a reliable device available".format(dev_prop_dict['Address']))
		return

def Disconnect_dev(dev_add):
	global bus
	global devices
	global adapter_path
	global managed_objects
	global ECCEL_connected
	exist = False
	
	print("-----------------------------------------------------")
	print("Disconnecting from {}...".format(dev_add['Address']))
	for path, ifaces in managed_objects.items():
		for iface_name in ifaces:
			if iface_name == btc.DEVICE_INTERFACE:				
				device_properties = ifaces[btc.DEVICE_INTERFACE]
				if 'Address' in device_properties:
					if device_properties['Address'] == dev_add['Address']:
						exist =True					
	if exist == True:		
		try:
			device_path = btu.device_address_to_path(dev_add['Address'], adapter_path)
			device_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME,device_path)
			device_interface = dbus.Interface(device_proxy, btc.DEVICE_INTERFACE)
			device_interface.Disconnect()
			
		except Exception as e:
			print("Disconnexion failed")
			e_name = e.get_dbus_name()
			print(e_name)
			print(e.get_dbus_message())
			return btc.RESULT_EXCEPTION
		else:
			print("Disconnexion succeed")
			
			if device_path == ECCEL_READER_PATH:
				print("ECCEL Reader removed")			
				ECCEL_connected = False
			return btc.RESULT_OK
	else:
		print("WARNING!! {} is unknow by the rpi".format(dev_add['Address']))
		return


def Remove_dev(dev_add):
	global bus
	global devices
	global adapter_path
	global managed_objects
	global ECCEL_connected
	exist = False
	
	print("-----------------------------------------------------")
	print("Removing {}...".format(dev_add['Address']))
	for path, ifaces in managed_objects.items():
		for iface_name in ifaces:
			if iface_name == btc.DEVICE_INTERFACE:				
				device_properties = ifaces[btc.DEVICE_INTERFACE]
				if 'Address' in device_properties:
					if device_properties['Address'] == dev_add['Address']:
						exist =True					
	if exist == True:		
		try:
			device_path = btu.device_address_to_path(dev_add['Address'], adapter_path)
			adapter_path = btc.BLUEZ_NAMESPACE + btc.ADAPTER_NAME
			#Acquire an adapter proxy object and its Adapter1 interface so that we can call its methods
			adapter_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME, adapter_path)
			adapter_interface = dbus.Interface(adapter_proxy, btc.ADAPTER_INTERFACE)
			adapter_interface.RemoveDevice(device_path)
		except Exception as e:
			print("Removing  failed")
			e_name = e.get_dbus_name()
			print(e_name)
			print(e.get_dbus_message())
			return btc.RESULT_EXCEPTION
		else:
			print("Removing succeed")
			
			if device_path == ECCEL_READER_PATH:
				print("ECCEL Reader removed")			
				ECCEL_connected = False
			return btc.RESULT_OK
	else:
		print("WARNING!! {} is unknow by the rpi".format(dev_add['Address']))
		return
			
def Is_dev_connected(dev_proxy):
	dev_prop = dbus.Interface(dev_proxy, btc.DBUS_PROPERTIES)
	is_connected = dev_prop.Get(btc.DEVICE_INTERFACE, "Connected")
	return is_connected

#utilities
def send(channel, *args):
	buf = cPickle.dumps(args)
	value = socket.htonl(len(buf))
	size = struct.pack("L", value)
	print("sending msg\n {}".format(args))
	try:
		channel.send(size)
		channel.send(buf)
	except Exception as e:
		print('send failed, make sure you are still connected. Exception: %s' %str(e))
		TCP_connected = False
		
	
def receive(channel):
	
	in_data_size = channel.recv(struct.calcsize("L"))
	try:
		size = socket.ntohl(struct.unpack("L", in_data_size)[0])
		if size > sys.maxsize:
			print("RECEIVED_OVERFLOW_ERRROR")
			return ''
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
	buf1 = cPickle.loads(buf)[0]
	return buf1
	
	
class TCPChatClient(object):
	"""A chat TCP client using select"""
	def __init__(self, name, port, host = HOSTNAME):
		global TCP_connected
		self.name = name
		TCP_connected = False
		self.host = host
		self.port = port
		#initial prompt
		self.prompt = '[' + '@'.join((name, socket.gethostname().split('.')[0])) + ']'
		#connect to server
		self.reconnect()
	def reconnect(self):
		global TCP_connected
		global TCP_sock
		try:
			TCP_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)	
			TCP_sock.connect((self.host,self.port))
			print("Now connected to server %s @ port %d" %(self.host, self.port))
			TCP_connected = True
			#send client name
			send(TCP_sock, 'NAME: '+self.name)
			data = receive(TCP_sock)
			
		except socket.error as e:
			print("Failed to connect to the server %s @ port %d, Exception: %s" %(self.host, self.port, str(e)))
		except Exception as e:
			print("failed to initialize socket, Exception: {}".format(e))		
		try:
			#received data contains the client address, set it
			addr = data.split('CLIENT: ')[1]
			self.prompt = '[' + '@'.join((self.name, addr)) + ']'
		except Exception as e:
			print("The received msg does not match the expected format")
		p = "FAILED" if ECCEL_connected == False else "SUCCESS"
		msg={
			"name":ECCEL_reader_name,
			"topic":"CONNEXION",
			"payload":p
			}	
		send(TCP_sock, msg);
	def run(self):
		"""
		chat cleint main loop
		"""
		global TCP_connected
		global TCP_sock
		print ("Starting TCP Chat client, Thread %d" %(threading.get_ident()  ))
		while TCP_connected:
			try:
				sys.stdout.write(self.prompt)
				sys.stdout.flush()
				#wait for input from socket
				readable, writable, exceptional = select.select([TCP_sock], [], [])
				for sock in readable:
					if sock == TCP_sock:
						data = receive(sock)
						if not data:
							print("Client shutting down")
							TCP_connected = False
							break
						else:
							if 'name' in data:
								if data['name'] == 'ACK':
									continue
							print("packet add to tcp queue \n{}".format(data))
							tcp_rx_queue.put(data)
							tcp_rx_evt.set()
							
					else:
						print("unknow file descriptor")
			except KeyboardInterrupt:
				print("\nClient interrupt")
				TCP_connected = False
				break
			except Exception as e:
				print("Exception occured in run: %s" %str(e))
				TCP_connected = False
				break
		
		TCP_sock.close()
		print ("Exiting TCP Chat client, Thread %d" %(threading.get_ident()  ))
		
	def send_msg(self):		
		global TCP_connected
		global TCP_sock
		global tcp_tx_queue
		while TCP_connected:
			to_send = tcp_tx_queue.get()
			send(TCP_sock, to_send)
		print ("Exiting TCP transmission client, Thread %d" %(threading.get_ident()  ))
	def clear(self):
		global TCP_connected
		global TCP_sock
		print("Clear: Client shutting down")
		TCP_sock.close()
		TCP_connected = False
						
		
def keyboardInterruptHandler(signum,frame):
	global client	
	global mainLoop
	global tcp_client_thread
	global EXIT_APP
	print("Keyboard interrupt handler")
	EXIT_APP = True
	#tcp_client_thread.clear()
	#tcp_client_thread.shutdown(wait = False,cancel_features = True)
	
	#mainLoop.quit()
	sys.exit(1)

class myThread (threading.Thread):
	
	def __init__(self, threadID, name, counter=0):
		   
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
	def run(self):
		global client
		global rfid_send_cmdd
		global processing_ble_msgs
		self.counter += 1
		if self.threadID == 2:
			rfid_send_cmdd.run()
		elif self.threadID == 3:
			processing_ble_msgs.run()


class TCPConnexionThreads (threading.Thread):
	def __init__(self, threadID, name, counter=0):		   
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
	def run(self):
		global client
		global TCP_connected
		global EXIT_APP
		self.counter += 1
		while not EXIT_APP:
			if TCP_connected == False:
				print("Trying to reconnect to the remote TCP server...")
				client.reconnect()
			else:
				client.run()
		client.clear()


class TCPTransmissionThread (threading.Thread):
	def __init__(self, threadID, name, counter=0):		   
		threading.Thread.__init__(self)
		self.threadID = threadID
		self.name = name
		self.counter = counter
	def run(self):
		global client
		global TCP_connected
		global EXIT_APP
		self.counter += 1
		while not EXIT_APP:
			if TCP_connected == False:
				print("Try to reconnect to the tcp server")
			else:
				client.send_msg()
		client.clear()

class RFID_send_cmdd(object):
	def __init__(self):
		print(" RFID_send_cmdd init")
	def run(self):
		global colision_ctr
		global EXIT_APP
		global tcp_rx_evt
		global tcp_rx_queue
		print ("Starting RFID_send_cmdd, Thread %d" %(threading.get_ident() ))
		while not EXIT_APP:
			#tcp_rx_evt.wait()
			basic_buf = tcp_rx_queue.get()
			tcp_rx_evt.clear()		
			if basic_buf == None:
				continue
			if "CLIENT: " in basic_buf:
				continue
				
			buf = basic_buf
			if "name" in buf:
				if buf["name"] == "ECCEL_READER":
					arg =[]							
					#reset_polling()
					if buf["topic"] == "INVENTORY_START":
						cmd = etp.CMD_LIST.CMD_ICODE_INVENTORY_START.value					
						Send_ECCEL_cmd(cmd, [])
						
					if buf["topic"] == "GET_TAG_CNT":
						cmd = etp.CMD_LIST.CMD_GET_TAG_COUNT.value
						Send_ECCEL_cmd(cmd, [])
						
					if buf["topic"] == "INVENTORY_NEXT":
						cmd = etp.CMD_LIST.CMD_ICODE_INVENTORY_NEXT.value				
						Send_ECCEL_cmd(cmd, [])
						
					if buf["topic"] == "GET_TAG_NAME":
						read_tag_name()
					if buf["topic"] == "SET_TAG_NAME":
						if "payload" in buf:
							arg = buf["payload"]							
							data = [ord(c) for c in arg]
							icode_write_blocks(etp.TAG_MEMORY_LAYOUT.TAG_NAME.value,etp.TAG_MEMORY_LAYOUT.TAG_NAME_CNT.value, data)
						
					if buf["topic"] == "GET_TAG_DATESTART":
						read_tag_datestart()
					if buf["topic"] == "SET_TAG_DATESTART":
						if "payload" in buf:
							arg = buf["payload"].split("/")		
							data = []				
							for i in range(0, 5-len(arg)):
								arg.append(0)		
							for i in range(0, 5):
								if arg[i] == "":
									arg[i] = '0'
								data.append(int(arg[i]))
							icode_write_blocks(etp.TAG_MEMORY_LAYOUT.TAG_DATESTART.value,etp.TAG_MEMORY_LAYOUT.TAG_DATESTART_CNT.value, data)
						 
					if buf["topic"] == "GET_TAG_DATESTOP":
						read_tag_datestop()
					if buf["topic"] == "SET_TAG_DATESTOP":
						if "payload" in buf:
							arg = buf["payload"].split("/")	
							data = []					
							for i in range(0, 5-len(arg)):
								arg.append(0)			
							for i in range(0, 5):
								if arg[i] == "":
									arg[i] = '0'
								data.append(int(arg[i]))
							icode_write_blocks(etp.TAG_MEMORY_LAYOUT.TAG_DATESTOP.value,etp.TAG_MEMORY_LAYOUT.TAG_DATESTOP_CNT.value, data)
						
					if buf["topic"] == "GET_TAG_EXPNBR":
						read_tag_expnbr()
					if buf["topic"] == "SET_TAG_EXPNBR":
						if "payload" in buf:						
							data = [int(buf["payload"])]
							icode_write_blocks(etp.TAG_MEMORY_LAYOUT.TAG_EXPNBR.value,etp.TAG_MEMORY_LAYOUT.TAG_EXPNBR_CNT.value, data)
						
					if buf["topic"] == "GET_TAG_COMMENTS":
						read_tag_comments()
					if buf["topic"] == "SET_TAG_COMMENTS":
						if "payload" in buf:
							arg = buf["payload"]							
							data = [ord(c) for c in arg]
							icode_write_blocks(etp.TAG_MEMORY_LAYOUT.TAG_COMMENTS.value,etp.TAG_MEMORY_LAYOUT.TAG_COMMENTS_CNT.value, data)
						
					
					if buf["topic"] == "READ_ALL":
						read_tag_all_infos()
					if buf["topic"] == "GET_SYS_INFOS":
						cmd = etp.CMD_LIST.CMD_ICODE_GET_SYSTEM_INFOS.value
						Send_ECCEL_cmd(cmd, arg)
						
					if buf["topic"] == "SET_POLLING":
						set_polling()
					if buf["topic"] == "RESET_POLLING":
						reset_polling()							
					#set_polling()
					
			
		print ("Exiting RFID_send_cmdd, Thread %d" %(threading.get_ident() ))
def read_tag_all_infos():
	read_tag_name()
	read_tag_expnbr()
	read_tag_datestart()
	read_tag_datestop()
	read_tag_comments()
	
def read_tag_expnbr():
	icode_read_blocks(etp.TAG_MEMORY_LAYOUT.TAG_EXPNBR.value,etp.TAG_MEMORY_LAYOUT.TAG_EXPNBR_CNT.value)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_DUMMY_COMMAND.value, [])
	while ecu.dmc_received == 0:
		pass
	ecu.dmc_received = 0
	nbr =0
	print("ecu.tag_expnbr_list : {}".format(ecu.tag_expnbr_list))	
	for i in range(0,len(ecu.tag_expnbr_list)):
		nbr += ecu.tag_expnbr_list[i] << (8*i)
	ecu.tag_expnbr_list = []
	msg["name"] = "Pepper_C1-1A6188"
	msg["topic"] = "GET_TAG_EXPNBR"
	msg["payload"] = nbr
	tcp_tx_queue.put(msg)
	
def read_tag_comments():
	icode_read_blocks(etp.TAG_MEMORY_LAYOUT.TAG_COMMENTS.value,etp.TAG_MEMORY_LAYOUT.TAG_COMMENTS_CNT.value)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_DUMMY_COMMAND.value, [])
	while ecu.dmc_received == 0:
		pass
	ecu.dmc_received = 0
	text =""
	for i in ecu.tag_comments_list:
		if i == 0:
			break
		text += chr(i)
	ecu.tag_comments_list = []
	msg["name"] = "Pepper_C1-1A6188"
	msg["topic"] = "GET_TAG_COMMENTS"
	msg["payload"] = text
	tcp_tx_queue.put(msg)


def read_tag_name():
	icode_read_blocks(etp.TAG_MEMORY_LAYOUT.TAG_NAME.value,etp.TAG_MEMORY_LAYOUT.TAG_NAME_CNT.value)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_DUMMY_COMMAND.value, [])
	while ecu.dmc_received == 0:
		pass
	ecu.dmc_received = 0
	text =""
	for i in ecu.tag_name_list:
		if i == 0:
			break
		text += chr(i)
	ecu.tag_name_list = []
	msg["name"] = "Pepper_C1-1A6188"
	msg["topic"] = "GET_TAG_NAME"
	msg["payload"] = text
	tcp_tx_queue.put(msg)
	

def read_tag_datestart():
	icode_read_blocks(etp.TAG_MEMORY_LAYOUT.TAG_DATESTART.value,etp.TAG_MEMORY_LAYOUT.TAG_DATESTART_CNT.value)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_DUMMY_COMMAND.value, [])
	while ecu.dmc_received == 0:
		pass
	ecu.dmc_received = 0
	msg["name"] = "Pepper_C1-1A6188"
	msg["topic"] = "GET_TAG_DATESTART"
	if len(ecu.tag_datestart_list) < 5:
		msg["payload"] = "ERR_OCCURED"
	else:
		date_str = str(ecu.tag_datestart_list[0]) + '/' + str(ecu.tag_datestart_list[1]) + '/' + str(ecu.tag_datestart_list[2])
		time_str = str(ecu.tag_datestart_list[3]) + ':' + str(ecu.tag_datestart_list[4])	
		msg["payload"] = date_str + ' | ' + time_str
	ecu.tag_datestart_list = []
	tcp_tx_queue.put(msg)

def read_tag_datestop():
	icode_read_blocks(etp.TAG_MEMORY_LAYOUT.TAG_DATESTOP.value,etp.TAG_MEMORY_LAYOUT.TAG_DATESTOP_CNT.value)
	Send_ECCEL_cmd(etp.CMD_LIST.CMD_DUMMY_COMMAND.value, [])
	while ecu.dmc_received == 0:
		pass
	ecu.dmc_received = 0	
	msg["name"] = "Pepper_C1-1A6188"
	msg["topic"] = "GET_TAG_DATESTOP"
	if len(ecu.tag_datestop_list) < 5:
		msg["payload"] = "ERR_OCCURED"
	else:
		date_str = str(ecu.tag_datestop_list[0]) + '/' + str(ecu.tag_datestop_list[1]) + '/' + str(ecu.tag_datestop_list[2])
		time_str = str(ecu.tag_datestop_list[3]) + ':' + str(ecu.tag_datestop_list[4])
		msg["payload"] = date_str + ' | ' + time_str
	ecu.tag_datestop_list = []
	tcp_tx_queue.put(msg)

def icode_read_blocks(start_block, block_count):
	global colision_ctr
	ecu.block_name = etp.MEMORY_BLOCK_NAME[start_block]
	if block_count == 0:
		return -1
	if start_block == 0:
		return -1
	cmd = etp.CMD_LIST.CMD_ICODE_READ_BLOCK.value
	nbr_read = block_count/MAX_BLCK_CNT_PER_READ
	current_block = start_block
	if nbr_read > 0:		
		for i in range(0, math.floor(nbr_read)):	
			args = [current_block, MAX_BLCK_CNT_PER_READ]
			Send_ECCEL_cmd(cmd, args)
			current_block += MAX_BLCK_CNT_PER_READ
			
	if current_block >= start_block + block_count:
		pass
	else:
		args = [current_block, 1]
		Send_ECCEL_cmd(cmd, args)
			
	return 0

def icode_write_blocks(start_block, block_count, data):
	if block_count == 0:
		return
	if start_block == 0:
		return
	
	ecu.block_name = etp.MEMORY_BLOCK_NAME[start_block].replace('G','S',1)	
	cmd = etp.CMD_LIST.CMD_ICODE_WRITE_BLOCK.value
	current_block = start_block
	data_len = len(data)	
	#data_len should be a multiple of 4
	l = (data_len)%4
	for i in range(0,4-l):
		data.append(0)
	data_len = len(data)	
	pos = etp.OCTETS_PER_ICODE_BLOCK*MAX_BLCK_CNT_PER_WRITE
	nbr_single_write = int(data_len / etp.OCTETS_PER_ICODE_BLOCK)
	nbr_double_write = math.floor(data_len / pos)
	data_read_cnt = 0
	if 	nbr_double_write > 0 :
		for i in range(0, nbr_double_write):
				args = [current_block, MAX_BLCK_CNT_PER_WRITE]
				for j in range(i*pos, (i+1)*pos):
					args.append(data[j])
				Send_ECCEL_cmd(cmd, args)
				current_block += MAX_BLCK_CNT_PER_WRITE	
		data_read_cnt = nbr_double_write * MAX_BLCK_CNT_PER_WRITE
		nbr_single_write = nbr_single_write - data_read_cnt
	for i in range(0, nbr_single_write):
		args = [current_block, 1]
		for j in range((i + data_read_cnt)*etp.OCTETS_PER_ICODE_BLOCK, data_len if (i+1+ data_read_cnt)*etp.OCTETS_PER_ICODE_BLOCK  > data_len else (i+1+ data_read_cnt)*etp.OCTETS_PER_ICODE_BLOCK):
			args.append(data[j])
		Send_ECCEL_cmd(cmd, args)
		current_block += 1	
		
class Process_BLE_msgs(object):
	def __init__(self):
		print(" Process BLE send msgs init")
	def run(self):
		global ble_evt
		global ble_queue
		global tcp_tx_queue
		global EXIT_APP
		
		print ("Starting Process BLE send msgs, Thread %d" %(threading.get_ident()  ))
		while not EXIT_APP:
			print("waiting to receive ble notification from the reader")
			ble_evt.wait()
			notif = ble_queue.get()
			t = notif[0]
			text = notif[1]
			ble_evt.clear()
			text_str = ''.join(' {:02X}'.format(c) for c in text)
			print('New {} notif, Value: {}'.format(ECCEL_reader_name,text_str))
			if not ECCEL_connected:
				print("ECCEL RFID Reader is not connected")
				time.sleep(1)
				continue
			if t == ECCEL_BLE_EVT:		
				if text[0] == 0xF5:
					buf = ecu.Process_ECCEL_read_data(text)
					if buf is None:
						continue
					msg["topic"] = buf["topic"] 
					msg["payload"] = buf["payload"]
				else:
					msg["topic"] = "ECCEL_ERR_NOTIF" 
					msg["payload"] = "ERR"
				msg["name"] = ECCEL_reader_name
				tcp_tx_queue.put(msg)
			text =""
		print ("Exiting Process BLE send msgs, Thread %d" %(threading.get_ident()  ))
			
if __name__ == '__main__':	
	parser = argparse.ArgumentParser(description = 'First trial program')
	parser.add_argument('-t','--timeout', action = "store", dest = "timeout", type = int, required = True)
	'''
	parser.add_argument('-a','--address', action = "store", dest = "address", required = True)
	parser.add_argument('-p', '--port', action = "store", dest = "port", type = int, required = True)
	'''
	given_args = parser.parse_args()
	port = TCP_PORT
	name = "ECCEL_RFID_READER"
	timeout = given_args.timeout
	
	print("Parsing bluetooth mac address from ble_devices.yaml")
	with open("ble_devices.yaml") as fd:
		data = yaml.load(fd, Loader = SafeLoader)
	addr = None
	if "dev_1" in data:
		addr = data["dev_1"].replace('_',':')
	if addr == None:
		sys.exit(-1)
	BTADDR_OF_INTEREST = addr
	print("BLE_DEVICE_MAC_ADDRESS:{}".format(BTADDR_OF_INTEREST))
	ECCEL_BLE_EVT = 0
	TCP_connected = False
	ECCEL_connected = False
	
	scanTime = timeout* 1000
	signal.signal(signal.SIGINT, keyboardInterruptHandler)
	
	client = TCPChatClient(name, port, host = TCP_HOSTNAME)
	rfid_send_cmdd = RFID_send_cmdd()
	processing_ble_msgs = Process_BLE_msgs()
	
	tcp_client_thread = TCPConnexionThreads(1, "tcp_client")
	rfid_send_cmdd_thread = myThread(2, "rfid_send_cmdd")
	processing_ble_msgs_thread = myThread(3, "Process_BLE_msgs")
	tcp_transmission_thread = TCPTransmissionThread(4, "tcp_tx")
	
	tcp_client_thread.damemon = True
	rfid_send_cmdd_thread.damemon = True
	processing_ble_msgs_thread.damemon = True
	tcp_transmission_thread.daemon = True
	
	tcp_client_thread.start()
	rfid_send_cmdd_thread.start()
	processing_ble_msgs_thread.start()
	tcp_transmission_thread.start()
	
	#dbus initialization steps
	dmg.DBusGMainLoop(set_as_default = True)
	bus = dbus.SystemBus()
	print("List of already known devices:")
	Get_known_dev()
	print("Scanning new one...")
	Discover_dev(scanTime)
