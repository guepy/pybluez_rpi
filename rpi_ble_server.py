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
import ble_tcp_client as ctc
import threading
from threading import Thread, Event
from queue import Queue
import argparse

sys.path.insert(0,'.')

ECCEL_READER_BDADDR='24:6F:28:1A:61:8A'

BTADDR_OF_INTEREST= sbc.SENSORTILE2_BLE_ADDR
TCP_HOSTNAME = 'localhost'
TCP_PORT = 0
#declare a list of path
path_list = []

#declare a dictionary of device with the scheme [device, properties]

	
#these service routines argument will be served by signal they are bound to as they
#are follow the signal-slot mechanism
#class RFIDReader(object):
bus = None
devices = None
found_src = None
found_chr = None
src_path_list  = None
chr_path_list = None
desc_path_list = None
ECCEL_send_cmd_path = None
ECCEL_read_path = None
SENSORTILE_motion_sensors_read_path = None
SENSORTILE_env_sensors_read_path = None
SENSORTILE_quaternions_read_path = None
tcp_queue = None
adapter_interface = None
adapter_path = None
adapter_proxy = None

device_interface = None

mainLoop = None
timer_id = None
managed_objects_nbr = 0
managed_objects = None
src_resolved_ok = False
quat_read_id = 0
quat_time_tag =0
rot_hex_x = 0
rot_hex_y = ''
rot_hex_z = ''
accLin_hex_x = ''
accLin_hex_y = ''
devices = {}
ECCEL_send_cmd_path = ''
ECCEL_read_path = ''
SENSORTILE_env_sensors_read_path = ''
SENSORTILE_motion_sensors_read_path = ''
SENSORTILE_quaternions_read_path = ''
connexion_ok = False

def Interfaces_added(path, interfaces):
	#interface is an array of dictionnary
	
	print("Interface added")
		
	if btc.DEVICE_INTERFACE in interfaces:
		device_properties = interfaces[btc.DEVICE_INTERFACE]
		if path not in devices:
			print("New device: {}".format(path))
			#New dictionnary entry
			devices[path] = device_properties
			dev = device_properties
			path_list.append(path)
			if 'Name' in dev:
				print("Device Name: {}".format(dev['Name']))
				
			if 'Address' in dev:
				print("Device address: {}".format(dev['Address']))
			if 'RSSI' in dev:
				print("Device RSSI: {}".format(dev['RSSI']))
			print("-----------------------------------------------------------")
		
	if btc.GATT_SERVICE_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_SERVICE_INTERFACE]
		print("Service Path: {}".format(path))
		src_path_list.append(path)
		if 'UUID' in prop:
			uuid = prop['UUID']
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
		if 'UUID' in prop:
			uuid = btu.dbus_to_python(prop['UUID'])
			print("Charractetitic UUID: {}".format(uuid))			
			print("Charractetitic Name: {}".format(btu.get_name_from_uuid(prop['UUID'])))
			if btc.ECCEL_READ_CHARACTERISTIC_UUID == uuid:
				Start_characteristic_notification(path)
				ECCEL_read_path = path
			if btc.ECCEL_WRITE_CHARACTERISTIC_UUID == uuid:
				ECCEL_send_cmd_path = path
			'''
			if uuid == sbc.SENSORTILE_ENV_SENSORS_CHAR_UUID:
				Start_characteristic_notification(path)	
				SENSORTILE_env_sensors_read_path = path		
			if uuid == sbc.SENSORTILE_ACC_GYRO_MAG_W2ST_CHAR_UUID:
				Start_characteristic_notification(path)
				SENSORTILE_motion_sensors_read_path = path
				
			'''
			if uuid == sbc.SENSORTILE_QUAT_CHAR_UUID:
				Start_characteristic_notification(path)
				SENSORTILE_quaternions_read_path = path
		flags = ''
		for f in prop['Flags']:
			flags = flags + f + ','
		print("Charractetitic Flags: {}".format(btu.dbus_to_python(flags)))	
		print("-----------------------------------------------------------")
		
	if btc.GATT_DESCRIPTOR_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_DESCRIPTOR_INTERFACE]
		print("-----------------------------------------------------------")
		print("Descriptor Path: {}".format(path))
		desc_path_list.append(path)
		if 'Name' in prop:	
			print("Descriptor Name: {}".format(btu.get_name_from_uuid(prop['Name'])))
		if 'UUID' in prop:
			print("Descriptor UUID: {}".format(btu.dbus_to_python(prop['UUID'])))	
		Read_descriptor_value(path)	
	return

def Start_characteristic_notification(chr_path):
	dev_chr_proxy = bus.get_object(	btc.BLUEZ_SERVICE_NAME, chr_path)
	dev_chr_interface = dbus.Interface(dev_chr_proxy, btc.GATT_CHARACTERISTIC_INTERFACE)
	bus.add_signal_receiver(Char_notification_received, dbus_interface = btc.DBUS_PROPERTIES,
		signal_name = "PropertiesChanged", path = chr_path, path_keyword = "path")

	try:
		notification_string = ''
		if chr_path == ECCEL_read_path:
			notification_string = 'ECCEL RFID Reader Card'
		if chr_path == SENSORTILE_motion_sensors_read_path:
			notification_string = 'SENSORTILE Motion Sensors'
		if chr_path == SENSORTILE_env_sensors_read_path:
			notification_string = 'SENSORTILE Environmental Sensors'
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
	print("Char notification received")
	if 'Value' in changed:
		if path == ECCEL_read_path:
			print("RFID Tag detected in the reach of the reader")
			text = btu.dbus_to_python(changed['Value'])
			text_str = ''.join(' {:02X}'.format(c) for c in text)
			print('Value: {}'.format(text_str))
			if text[0] == 0xF5:
				ecu.Process_ECCEL_read_data(text)
			return btc.RESULT_OK
		if path == SENSORTILE_motion_sensors_read_path:
			print("SENSORTILE Motion sensor update")
			text = []
			text = btu.dbus_to_python(changed['Value'])
			text_str = ''.join(' {:02X}'.format(c) for c in text)
			print('Bare Value: {}'.format(text_str))
			
			if len(text) < 10 :
				print('The size of received data does not match the one expected')
			else:
				time_tag = (text[0] << 3) + ((text[1] << 3)<< 8)
				
				acc_x = (ctypes.c_short(text[2]  + (text[3] << 8))).value
				acc_y = (ctypes.c_short(text[4]  + (text[5] << 8))).value
				acc_z = (ctypes.c_short(text[6]  + (text[7] << 8))).value
				
				gyro_x = (ctypes.c_short((text[8]) + ((text[9])<< 8))).value/10
				gyro_y = (ctypes.c_short((text[10]) + ((text[11])<< 8))).value/10
				gyro_z = (ctypes.c_short((text[12]) + ((text[13])<< 8))).value/10
				
				#This interpretation of magneto value doesn't take calibration data into account (but should)			
				mag_x = (ctypes.c_short(text[14]  + (text[15] << 8))).value
				mag_y = (ctypes.c_short(text[16]  + (text[17] << 8))).value
				mag_z = (ctypes.c_short(text[18]  + (text[19] << 8))).value
				with open('3d_fusion_data.csv', mode ='a') as fd:
					fd_writer = csv.writer(fd, delimiter=',')
					fd_writer.writerow([time_tag,acc_x, acc_y, acc_z, gyro_x, gyro_y, gyro_z,mag_x, mag_y, mag_z])
				print('Time stamp: {}'.format(time_tag))
				print('\tacc_x: {}, acc_y: {}, acc_z: {}'.format(acc_x, acc_y, acc_z))
				print('\tgyro_x: {}, gyro_y: {}, gyro_z: {}'.format(gyro_x, gyro_y, gyro_z))
				print('\tmag_x: {}, mag_y: {}, mag_z: {}'.format(mag_x, mag_y, mag_z))

		if path == SENSORTILE_env_sensors_read_path:
			print("SENSORTILE Env sensor update")
			text = []
			text = btu.dbus_to_python(changed['Value'])
			text_str = ''.join(' {:02X}'.format(c) for c in text)
			print('Bare Value: {}'.format(text_str))
			if len(text) < 8 :
				print('The size of received data does not match the one expected')
			else:
				time_tag = (text[0] << 3) + ((text[1] << 3)<< 8)
				
				press = (ctypes.c_int((text[2]  + (text[3] << 8)  + (text[4] << 16)  + (text[5] << 24))).value)/100
				#hum = text[6]  + (text[7] << 8)
				#temp = text[8]  + (text[9] << 8)
				temp = (ctypes.c_short((text[6]  + (text[7] << 8))).value)/10
				
				print('Time stamp: {}'.format(time_tag))
				print('\nPressure: {}, humidity: {}, temperature: {}'.format(press, 0, temp))			
				

		if path == SENSORTILE_quaternions_read_path:
			print("SENSORTILE quaternions update")
			text = btu.dbus_to_python(changed['Value'])
			text_str = ''.join(' {:02X}'.format(c) for c in text)
			print('Bare Value: {}'.format(text_str))
			read_len = len(text)
			
			if read_len != sbc.QUAT_UPDATE_SIZE :
				print('The size of received data does not match the one expected')
				return
			'''
			if quat_read_id == -1:
				ctr=0
				for i in range(18):
					if text[i] != 0xFF:
						break
					ctr += 1
				if ctr == 18:
					quat_read_id = 0
				else:
					print("This is not the first block")
					return
					
			if quat_read_id == 0:
				quat_time_tag = (text[18] << 3) + ((text[19] << 3)<< 8)
				print('First batch received')
				quat_read_id = 1
				return
			'''
			
			if quat_read_id == 0:
				#text = text[::-1]
				l = text[0:4:1]
				l = l[::-1]
				rot_hex_x = ''.join('{:02X}'.format(c) for c in l)
				l = text[4:8:1]
				l = l[::-1]
				rot_hex_y = ''.join('{:02X}'.format(c) for c in l)
				l = text[8:12:1]
				l = l[::-1]
				rot_hex_z = ''.join('{:02X}'.format(c) for c in l)
				l = text[12:16:1]
				l = l[::-1]
				accLin_hex_x = ''.join('{:02X}'.format(c) for c in l)
				l = text[16:20:1]
				l = l[::-1]
				accLin_hex_y = ''.join('{:02X}'.format(c) for c in l)
				quat_read_id += 1
				#print('first batch received')
				return
			if quat_read_id == 1:
				l = text[0:4:1]
				l = l[::-1]
				accLin_hex_z = ''.join('{:02X}'.format(c) for c in l)
				l = text[4:8:1]
				l = l[::-1]
				quat_hex_x = ''.join('{:02X}'.format(c) for c in l)
				l = text[8:12:1]
				l = l[::-1]
				quat_hex_y = ''.join('{:02X}'.format(c) for c in l)
				l = text[12:16:1]
				l = l[::-1]
				quat_hex_z = ''.join('{:02X}'.format(c) for c in l)
				l = text[16:20:1]
				l = l[::-1]
				quat_hex_r = ''.join('{:02X}'.format(c) for c in l)
				
				#print('second batch received')
				rot_x = struct.unpack('!f', bytes.fromhex(rot_hex_x))[0]
				rot_y = struct.unpack('!f', bytes.fromhex(rot_hex_y))[0]
				rot_z = struct.unpack('!f', bytes.fromhex(rot_hex_z))[0]
				
				accLin_x = struct.unpack('!f', bytes.fromhex(accLin_hex_x))[0]
				accLin_y = struct.unpack('!f', bytes.fromhex(accLin_hex_y))[0]
				accLin_z = struct.unpack('!f', bytes.fromhex(accLin_hex_z))[0]
				
				quat_x = struct.unpack('!f', bytes.fromhex(quat_hex_x))[0]
				quat_y = struct.unpack('!f', bytes.fromhex(quat_hex_y))[0]
				quat_z = struct.unpack('!f', bytes.fromhex(quat_hex_z))[0]
				quat_r = struct.unpack('!f', bytes.fromhex(quat_hex_r))[0]
				'''
				print('\nrot_x: {}, rot_y: {}, rot_z: {}'.format(rot_x, rot_y,rot_z))
				print('\naccLin_x: {}, accLin_y: {}, accLin_z: {}'.format(accLin_x, accLin_y,accLin_z))
				print('\nquat_x: {}, quat_y: {}, quat_z: {}, quat_r: {}'.format(quat_x, quat_y,quat_z,quat_r))
				'''
				quat_read_id = 0				
				with open('complete_fusion_data.csv', mode ='a') as fd:
					fd_writer = csv.writer(fd, delimiter=',')
					fd_writer.writerow([rot_x, rot_y,rot_z,accLin_x, accLin_y,accLin_z, quat_x, quat_y,quat_z,quat_r])
				'''
				time_tag = (text[0] << 3) + ((text[1] << 3)<< 8)
				quat_x_1 = (ctypes.c_int(text[2]  + (text[3] << 8) ).value)/10000
				quat_y_1 = (ctypes.c_int(text[4]  + (text[5] << 8) ).value)/10000
				quat_z_1 = (ctypes.c_int(text[6]  + (text[7] << 8) ).value)/10000
				
				quat_x_2 = (ctypes.c_int(text[8]  + (text[9] << 8) ).value)/10000
				quat_y_2 = (ctypes.c_int(text[10]  + (text[11] << 8) ).value)/10000
				quat_z_2 = (ctypes.c_int(text[12]  + (text[13] << 8) ).value)/10000
				
				quat_x_3 = (ctypes.c_int(text[14]  + (text[15] << 8) ).value)/10000
				quat_y_3 = (ctypes.c_int(text[16]  + (text[17] << 8) ).value)/10000
				quat_z_3 = (ctypes.c_int(text[18]  + (text[19] << 8) ).value)/10000
				
				with open('quaternion_data.csv', mode ='a') as fd:
					fd_writer = csv.writer(fd, delimiter=',')
					fd_writer.writerow([time_tag-20,quat_x_1, quat_y_1,quat_z_1])
					fd_writer.writerow([time_tag-10,quat_x_2, quat_y_2,quat_z_2])
					fd_writer.writerow([time_tag,quat_x_3, quat_y_3,quat_z_3])
				#hum = text[6]  + (text[7] << 8)
				#temp = text[8]  + (text[9] << 8)
				temp = (ctypes.c_short((text[6]  + (text[7] << 8))).value)/10
				
				print('Time stamp: {}'.format(time_tag))
				print('\nquat_x_1: {}, quat_y_1: {}, quat_z_1: {}'.format(quat_x_1, quat_y_1, quat_z_1))					
	'''
		return btc.RESULT_OK
			
def Read_characteristic_value(chr_path):
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
	to_send = ecu.Format_ECCEL_cmd(cmd, arg)
	if ECCEL_send_cmd_path != '':
		Write_characteristic_value(ECCEL_send_cmd_path, to_send)
	else:
		print('unknow char path')
	
def Read_descriptor_value(chr_path):
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
	dev_chr_proxy = bus.get_object(	btc.BLUEZ_SERVICE_NAME, chr_path)
	dev_chr_interface = dbus.Interface(dev_chr_proxy, btc.GATT_CHARACTERISTIC_INTERFACE)
	try:
		#text = btu.text_to_ascii_array(value)
		dev_chr_interface.WriteValue(value, {})
	except Exception as e:
		print('failed to write characteristic {}'.format(chr_path))
		print(e.get_dbus_name())
		print(e.get_dbus_message())
		return btc.RESULT_EXCEPTION
	else:
		
		print('write to {} suceeed'.format(chr_path))
		return btc.RESULT_OK
			
def Discover_dev(timeout):
	adapter_path = btc.BLUEZ_NAMESPACE + btc.ADAPTER_NAME
	#Acquire an adapter proxy object and its Adapter1 interface so that we can call its methods
	adapter_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME, adapter_path)
	adapter_interface = dbus.Interface(adapter_proxy, btc.ADAPTER_INTERFACE)
	
	#Register signal_handler so we can asynchronously reprted new device discovered
	#Remember the InterfaceAdded signal is sent each time the adapter receive a discovery 
	#packet from a device unknow by its device list
	bus.add_signal_receiver(Interfaces_added, dbus_interface = btc.DBUS_OM_IFACE,
		signal_name = "InterfacesAdded")
	print("ok")
	bus.add_signal_receiver(Interfaces_removed, dbus_interface = btc.DBUS_OM_IFACE,
		signal_name = "InterfacesRemoved")
	print("ok")
	bus.add_signal_receiver(Properties_changed, dbus_interface = btc.DBUS_PROPERTIES,
		signal_name = "PropertiesChanged", path_keyword = "path")

	print("ok")
	mainLoop = GLib.MainLoop()
	timer_id = GLib.timeout_add(timeout, Discovery_timeout)
	adapter_interface.StartDiscovery(byte_arrays = True)
	#Disconnect_dev(BTADDR_OF_INTEREST)	
	for path in path_list:
		dev_dict = devices[path]
		Disconnect_dev(dev_dict)
		Remove_dev(dev_dict)
	mainLoop.run()

def Discovery_timeout(self):
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
	return True

def Interfaces_removed(self, path, interfaces):
	if not btc.DEVICE_INTERFACE in interfaces:
		return
	if path in devices:
		dev = devices[path]
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
	if interface == btc.DEVICE_INTERFACE:
		if path in devices:
			devices[path] = dict(devices[path].items())
			devices[path].update(changed.items())
		else:
			devices[path] = changed
			
		dev = devices[path]
		print("Properties changed\nPath: {}".format(path))
		while evt.is_set():
			pass
		evt.set()
		tcp_queue.put(("Properties changed\nPath: {}".format(path)), evt)
		if 'Name' in dev:
			print("Device Name: {}".format(btu.dbus_to_python(dev['Name'])))
		if 'Address' in dev:
			print("Device Address: {}".format(btu.dbus_to_python(dev['Address'])))
		if 'RSSI' in dev:
			print("Device RSSI: {}".format(btu.dbus_to_python(dev['RSSI'])))
			
		if 'ServicesResolved' in changed:
			src_resolved_ok = btu.dbus_to_python(changed['ServicesResolved'])
			print("ServicesResolved: {}".format(src_resolved_ok))
			
		print("-----------------------------------------------------------")

def Get_known_dev():
	global managed_objects_nbr
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

def Try_custom_ECCEL_cmds():
	cmd = etp.CMD_LIST.CMD_GET_TAG_COUNT.value
	arg = []
	Send_ECCEL_cmd(cmd, arg)
	cmd = etp.CMD_LIST.CMD_GET_UID.value
	arg = [0]
	Send_ECCEL_cmd(cmd, arg)
	cmd = etp.CMD_LIST.CMD_MFDF_APP_IDSRROR.value
	arg = [1]
	Send_ECCEL_cmd(cmd, arg)
	cmd = etp.CMD_LIST.CMD_MFDF_GET_FREEMEM.value
	arg = []
	Send_ECCEL_cmd(cmd, arg)
	cmd = etp.CMD_LIST.CMD_MFU_READ_PAGE.value
	arg = [1,2]
	Send_ECCEL_cmd(cmd, arg)
	
def Connect_dev(dev_prop_dict):
	dev_add = dev_prop_dict['Address']
	if 'Name' in dev_prop_dict:		
		try:
			device_path = btu.device_address_to_path(dev_add, adapter_path)
			device_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME,device_path)
			device_interface = dbus.Interface(device_proxy, btc.DEVICE_INTERFACE)
			if(Is_dev_connected(device_proxy) == True):
				print("Device {} is already connected".format(btu.dbus_to_python(dev_prop_dict['Name'])))
				Try_custom_ECCEL_cmds()

				return
			else:
				print("-----------------------------------------------------")
				print("Connecting to {}...".format(dev_add))
				device_interface.Connect()
		except Exception as e:
			print("Connexion failed")
			e_name = e.get_dbus_name()
			print(e_name)
			print(e.get_dbus_message())
			if("UnknowObject" in e_name):
				print("The device may not be in the reach of the adapter")
			return btc.RESULT_EXCEPTION
		else:
			print("Connection succeed")
			return btc.RESULT_OK
	else:
		print("WARNING!! Skiping connexion to {} as I think it is not a reliable device available".format(dev_prop_dict['Address']))
		return

def Disconnect_dev(dev_add):
	exist = False
	global managed_objects	
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
			print("Disconnection succeed")
			return btc.RESULT_OK
	else:
		print("WARNING!! {} is unknow by the rpi".format(dev_add['Address']))
		return


def Remove_dev(dev_add):
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
			return btc.RESULT_OK
	else:
		print("WARNING!! {} is unknow by the rpi".format(dev_add['Address']))
		return
		
def Is_dev_connected(dev_proxy):
	dev_prop = dbus.Interface(dev_proxy, btc.DBUS_PROPERTIES)
	is_connected = dev_prop.Get(btc.DEVICE_INTERFACE, "Connected")
	return is_connected
	
def tag_reader(timeout):
	with open('complete_fusion_data_trash.csv', mode ='a', newline = '') as fd:
		fd_writer = csv.writer(fd, delimiter=',')
		fd_writer.writerow([(datetime.now()).strftime('%d/%m/%Y %H:%M:%S')])
		fd_writer.writerow(['rot_x', 'rot_y', 'rot_z', 'acc_x', 'acc_y', 'acc_z', 'quat_x', 'quat_y', 'quat_z', 'quat_r'])
	scanTime = timeout* 1000
	#dbus initialization steps
	dmg.DBusGMainLoop(set_as_default = True)

	print("List of already known devices:")
	Get_known_dev()
	print("Scanning new one...")
	Discover_dev(scanTime)
			
def send_tcp_packets(name, port, tcp_queue):	
	client = ctc.TCPChatClient(name, port)
	client.run(tcp_queue)

if __name__ == '__main__':	
	parser = argparse.ArgumentParser(description = 'First trial program')
	parser.add_argument('-t','--timeout', action = "store", dest = "timeout", type = int, required = True)
	given_args = parser.parse_args()
	timeout = given_args.timeout
	tcp_queue = Queue()
	evt = Event()
	
	with open('complete_fusion_data_trash.csv', mode ='a', newline = '') as fd:
		fd_writer = csv.writer(fd, delimiter=',')
		fd_writer.writerow([(datetime.now()).strftime('%d/%m/%Y %H:%M:%S')])
		fd_writer.writerow(['rot_x', 'rot_y', 'rot_z', 'acc_x', 'acc_y', 'acc_z', 'quat_x', 'quat_y', 'quat_z', 'quat_r'])
	scanTime = timeout* 1000
	#dbus initialization steps
	dmg.DBusGMainLoop(set_as_default = True)
	bus = dbus.SystemBus()

	print("List of already known devices:")
	Get_known_dev()
	print("Scanning new one...")
	Discover_dev(scanTime)

