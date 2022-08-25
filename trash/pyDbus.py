#!/usr/bin/python3
import dbus
import os
import sys
import bluetooth_utils
import bluetooth_constants
import dbus.service
import dbus.mainloop.glib as dmg
from gi.repository import GLib

sys.path.insert(0,'.')
# define the bluetooth controler
adapter_interface = None
mainLoop = None
timer_id = None

#declare a list of device
device = {}

def interfaces_added(path, interfaces):
	#interface is an array of dic
class Calculator(dbus.service.Object):
	#Constructor
	def __init__(self, bus):
		self.path = "/com/example/calculator"
		dbus.service.Object.__init__(self, bus, self.path)
	@dbus.service.method("com.example.calculator_interface", in_signature="ii", out_signature="i")
	def Add(self, a, b):
		my_sum = a + b
		print("{} + {} = {}".format(a, b, my_sum))
		return my_sum
		
dmg.DBusGMainLoop(set_as_default = True)
	
bus = dbus.SystemBus()

calc = Calculator(bus)
mainLoop = GLib.MainLoop()
print("waiting for some calculations to do...\n")
#bus.add_signal_receiver(greeting_sig_rcv, dbus_interface = "com.example.greeting", signal_name = "Greeting_signal")

mainLoop.run()
