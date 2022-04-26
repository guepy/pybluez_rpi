#!/usr/bin/python3

from gi.repository import GLib
import dbus
import os
import sys
import bluetooth_utils as btu
import bluetooth_constants as btc
import dbus.service
import dbus.mainloop.glib as dmg


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
src_path = None
chr_path = None

#declare a list of path
path_list = []

#declare a dictionary of device with the scheme [device, properties]
devices = {}

#these service routines argument will be served by signal they are bound to as they
#are follow the signal-slot mechanism
def Interfaces_added(path, interfaces):
	#interface is an array of dictionnary
	global devices
	global found_src
	global found_chr
	global src_path 
	global chr_path 
	
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
		print("-----------------------------------------------------------")
		print("Service Path: {}".format(path))
		if 'UUID' in prop:
			uuid = prop['UUID']
			print("Service UUID: {}".format(btu.dbus_to_python(uuid)))			
			print("Service Name: {}".format(btu.get_name_from_uuid(uuid)))
			if btc.DEVICE_INF_SVC_UUID == uuid:
				found_src = True
				src_path = path
			
		
	if btc.GATT_CHARACTERISTIC_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_CHARACTERISTIC_INTERFACE]
		print("-----------------------------------------------------------")
		print("Charractetitic Path: {}".format(path))
		if 'UUID' in prop:
			uuid = prop['UUID']
			print("Charractetitic UUID: {}".format(btu.dbus_to_python(uuid)))			
			print("Charractetitic Name: {}".format(btu.get_name_from_uuid(uuid)))
			if btc.MODEL_NUMBER_UUID == uuid:
				found_chr = True
				chr_path = path
		
		for f in prop['flags']:
			flags = flags + f + ','
		print("Charractetitic Flags: {}".format(btu.dbus_to_python(flags)))	
		
	if btc.GATT_DESCRIPTOR_INTERFACE in interfaces:
		prop = interfaces[btc.GATT_DESCRIPTOR_INTERFACE]
		print("-----------------------------------------------------------")
		print("Descriptor Path: {}".format(path))
		if 'UUID' in prop:
			print("SDescriptor UUID: {}".format(btu.dbus_to_python(prop['UUID'])))			
			print("Descriptor Name: {}".format(btu.get_name_from_uuid(prop['UUID'])))
	return

def Required_service_found():
	global found_src
	global found_chr
	global src_path 
	global chr_path 
	if found_chr and found_src:
		print("Service discovery Ok on device {}".format(src_path))
	
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
		Connect_dev(devices[path])
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
	if interface != btc.DEVICE_INTERFACE:
		return
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
	
	exist = False
	
	print("-----------------------------------------------------")
	print("Disconnecting from {}...".format(dev_add['Address']))
	for path, ifaces in managed_objects.items():
		for iface_name in ifaces:
			if iface_name == btc.DEVICE_INTERFACE:				
				device_properties = ifaces[btc.DEVICE_INTERFACE]
				if 'Address' in device_properties:
					if device_properties['Address'] == dev_add:
						exist =True					
	if exist == True:		
		try:
			device_path = btu.device_address_to_path(dev_add, adapter_path)
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
		
def Is_dev_connected(dev_proxy):
	dev_prop = dbus.Interface(dev_proxy, btc.DBUS_PROPERTIES)
	is_connected = dev_prop.Get(btc.DEVICE_INTERFACE, "Connected")
	return is_connected
	
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
	
			
			
		
