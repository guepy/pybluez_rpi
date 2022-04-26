#!/usr/bin/python3

from gi.repository import GLib
import dbus
import os
import sys
import bluetooth_utils as btu
import btc
import dbus.service
import dbus.mainloop.glib as dmg
import eccel_tag_param as etp
import eccel_utils as ecu
sys.path.insert(0,'.')
# define the bluetooth controler
adapter_interface = None
adapter_path = None
adapter_proxy = None

device_interface = None

mainLoop = None
timer_id = None
bus = None
managed_objects_nbr = 0
found_src = False
found_chr = False
src_path_list = []
chr_path_list = []
desc_path_list = []
managed_objects = None
src_resolved_ok = False

SENSORTILE_BDADDR='24:6F:28:1A:61:8A'

#declare a list of path
path_list = []

#declare a dictionary of device with the scheme [device, properties]
devices = {}
ECCEL_send_cmd_path = ''
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
	global ECCEL_send_cmd_path
	
	print("Interface added\nPath: {}\n interfaces {}".format(path, btu.dbus_to_python(interfaces)))
		
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
			if btc.ECCEL_WRITE_CHARACTERISTIC_UUID == uuid:
				ECCEL_send_cmd_path = path
		flags = ''
		for f in prop['Flags']:
			flags = flags + f + ','
		print("Charractetitic Flags: {}".format(btu.dbus_to_python(flags)))	
		Read_characteristic_value(path)
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
	global bus
	dev_chr_proxy = bus.get_object(	btc.BLUEZ_SERVICE_NAME, chr_path)
	dev_chr_interface = dbus.Interface(dev_chr_proxy, btc.GATT_CHARACTERISTIC_INTERFACE)
	bus.add_signal_receiver(Char_notification_received, dbus_interface = btc.DBUS_PROPERTIES,
		signal_name = "PropertiesChanged", path = chr_path, path_keyword = "path")

	try:
		dev_chr_interface.StartNotify()
	except Exception as e:
		print('failed to register notifications on path {}'.format(chr_path))
		print(e.get_dbus_name())
		print(e.get_dbus_message())
		return btc.RESULT_EXCEPTION
	else:
		print('successfully register to notifications on path {}'.format(chr_path))
		return btc.RESULT_OK

def Char_notification_received(interface, changed, not_used, path):
	print("Char notification received")
	if 'Value' in changed:
		text = btu.dbus_to_python(changed['Value'])
		text_str = ''.join(' {:02X}'.format(c) for c in text)
		print('Value: {}'.format(text_str))
		if text[0] == 0xF5:
			ecu.Process_ECCEL_read_data(text)
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
	global ECCEL_send_cmd_path
	to_send = ecu.Format_ECCEL_cmd(cmd, arg)
	if ECCEL_send_cmd_path != '':
		Write_characteristic_value(ECCEL_send_cmd_path, to_send)
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
	global bus
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
	#Disconnect_dev(SENSORTILE_BDADDR)	
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
	
	#GLib.source_remove(timer_id)
	#mainLoop.quit()
	#adapter_interface.StopDiscovery()
	#bus.remove_signal_receiver(Interfaces_added, "InterfacesAdded")
	#bus.remove_signal_receiver(Interfaces_removed, "InterfacesRemoved")
	#bus.remove_signal_receiver(Properties_changed, "PropertiesChanged")
	List_dev_found()
	for path in path_list:
		dev_dict = devices[path]
		if dev_dict['Address'] == SENSORTILE_BDADDR:
			Connect_dev(dev_dict)
	return True

def Interfaces_removed(path, interfaces):
	global devices
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
	global devices
	global src_resolved_ok
	if interface == btc.DEVICE_INTERFACE:
		if path in devices:
			devices[path] = dict(devices[path].items())
			devices[path].update(changed.items())
		else:
			devices[path] = changed
			
		dev = devices[path]
		print("Properties changed\nPath: {}".format(path))
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
	global bus
	global devices
	global managed_objects
	global path_list
	object_manager = dbus.Interface(bus.get_object(btc.BLUEZ_SERVICE_NAME, "/"), 
	btc.DBUS_OM_IFACE)
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

def Connect_dev(dev_prop_dict):
	global bus
	global devices
	global adapter_path
	dev_add = dev_prop_dict['Address']
	if 'Name' in dev_prop_dict:		
		try:
			device_path = btu.device_address_to_path(dev_add, adapter_path)
			device_proxy = bus.get_object(btc.BLUEZ_SERVICE_NAME,device_path)
			device_interface = dbus.Interface(device_proxy, btc.DEVICE_INTERFACE)
			if(Is_dev_connected(device_proxy) == True):
				print("Device {} is already connected".format(btu.dbus_to_python(dev_prop_dict['Name'])))
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
	global bus
	global devices
	global adapter_path
	global managed_objects
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
			print("Disconnection succeed")
			return btc.RESULT_OK
	else:
		print("WARNING!! {} is unknow by the rpi".format(dev_add['Address']))
		return


def Remove_dev(dev_add):
	global bus
	global devices
	global adapter_path
	global managed_objects
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
	
if(len(sys.argv) != 2):
	print("Usage: {} timeout(in secs)\n".format(sys.argv[0]))
	sys.exit(1)

scanTime = int(sys.argv[1]) * 1000
#dbus initialization steps
dmg.DBusGMainLoop(set_as_default = True)

bus = dbus.SystemBus()
print("List of already known devices:")
Get_known_dev()
print("Scanning new one...")
Discover_dev(scanTime)
	
			
			
		
