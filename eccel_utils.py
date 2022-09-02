import eccel_tag_param as etp
import math

ret = {
"topic": "",
"payload":"",
"name":""
}
SET_POLLING = 0	
block_name = "UNSAVED_BLOCK_NAME"
stop_reading = 0
dmc_received = 0
tag_name_list = []
tag_comments_list = []
tag_datestart_list = []
tag_datestop_list = []
tag_expnbr_list = []
current_tag_UUID = ""
readall = 0

#The function formats cmd to be send to the RFID Reader
def Format_ECCEL_cmd(cmd, arg):
	global SET_POLLING
	global block_name
	#send_data template
	#[STX byte(0xF5), cmd_len(2 bytes, LSB first),cmd_len XOR 0xFFFF(2 bytes), ASYNC Byte(0xFE), ECCEL_cmd(1byte), cmd_arg(n bytes),CRC code(2 bytes)]  
	#cmd_len = ASYNC_byte length + ECCEL_cmd length + cmd_arg length + CRC_code length
	# cmd_arg template for cmd = GET_UID_CMD
	# [Tag type(1 byte), TAG param(SAK for MIFARE tags, DSFID for ICODE tags. 1byte), TAG UID bytes(8 bytes max)]
	to_send = list()
	to_send.append(0xF5)
	data = [cmd & 0xFF]
	arg_len = len(arg)
	if arg_len == 0: #No argument has been passed to the cmd
		to_send.append(0x3)
		to_send.append(0)
		to_send.append(0xFC)
		to_send.append(0xFF)
		to_send.append(cmd & 0xFF)		
		cmd_crc = etp.GetCCITTCRC(data)
		to_send.append(cmd_crc & 0x00FF)
		to_send.append((cmd_crc & 0xFF00) >> 8)
	else:		
		# cmd_len = len(cmd + arg + crc)
		cmd_len = 1 + 2 #init
		to_send.append(cmd & 0xFF)	
				
		if cmd == etp.CMD_LIST.CMD_SET_POLLING.value:
			if int(arg[0]) == 1:
				SET_POLLING = 1
			else:
				SET_POLLING = 0
		for a in arg:
			if a < 0xFF:
				to_send.append(a & 0xFF)
				data.append(a & 0xFF)
				cmd_len += 1
			else:
				to_send.append(a & 0xFF)
				to_send.append(((a & 0xFF00)>>8) & 0xFF)
				data.append(a & 0xFF)
				data.append(((a & 0xFF00)>>8) & 0xFF)
				cmd_len += 2
		print('data is {}'.format(data))
		cmd_crc = etp.GetCCITTCRC(data)
		
		to_send.insert(1,cmd_len & 0x00FF)
		to_send.insert(2,(cmd_len & 0xFF00) >> 8)
		cmd_len_xor = (cmd_len ^ 0xFFFF) & 0xFFFF
		to_send.insert(3,cmd_len_xor & 0x00FF)
		to_send.insert(4,(cmd_len_xor & 0xFF00) >> 8)	
		to_send.append(cmd_crc & 0x00FF)
		to_send.append((cmd_crc & 0xFF00) >> 8)
	to_send_str = ''.join(' {:02X}'.format(c) for c in to_send)
	print('command send to ECCEL reader {}'.format(to_send_str))
	return to_send
	
# THe function decodes data received from the RFID reader
def Process_ECCEL_read_data(read_data):
	global ret
	global stop_reading
	global dmc_received
	global current_tag_UUID
	global readall
	#received data
	#[STX byte(0xF5), cmd_len(2 bytes, LSB first),cmd_len XOR 0xFFFF(2 bytes), ASYNC Byte(0xFE), ECCEL_cmd(1byte), cmd_arg(n bytes),CRC code(2 bytes)]  
	#cmd_len = ECCEL_cmd length + cmd_arg length + CRC_code length
	# cmd_arg template for cmd = GET_UID_CMD
	# [Tag type(1 byte), TAG param(SAK for MIFARE tags, DSFID for ICODE tags. 1byte), TAG UID bytes(8 bytes max)]
	async_pck = 0
	found = 0
	pck_type = read_data[5]
	'''
	GENERAL CMDs
	'''
	if pck_type == etp.CMD_LIST.CMD_ASYNC.value:
		print('ASYNC packet type')
		found = 1
		async_pck = 1
	if pck_type == etp.CMD_LIST.CMD_ACK.value:
		print('ACK packet type')
		found = 1
	cmd_len = read_data[1] + (read_data[2] >> 8)
	cmd = read_data[6]
	
	if pck_type == etp.CMD_LIST.CMD_ERROR.value:
		print('ECCEL reader failed to execute %s command'%etp.RFID_CMD_NAME[cmd])
		ret["topic"] = "ERR"
		ret["payload"] = etp.RFID_CMD_NAME[cmd]
		return ret
	
	if found == 0:
		print('Unknow packet type')
		ret["topic"] = "PCK_TYPE"
		ret["payload"] = "UNKNOW"
		return ret
		
	'''
	General commands
	'''
	if cmd == etp.CMD_LIST.CMD_GET_UID.value: 		
		tag_type = read_data[7]
		tag_param = read_data[8]
		len_UID = cmd_len - 6 # 1Byte for ACK ,1 for cmd, 1 for tag_type, 1 for tag_param, 2 for CRC code
		tag_UID = read_data[9:9+len_UID]
		tag_UID_str = ''.join(' {:02X}'.format(c) for c in tag_UID)
		ttype = ""
		if tag_type in etp.TAG_TYPE:
			ttype = etp.TAG_TYPE[tag_type]
			print("TAG type is {}".format(ttype))
		else:
			ttype = "UNKNOW"
			print("TAG type is UNKNOW")
		if current_tag_UUID != tag_UID_str:
			current_tag_UUID = tag_UID_str
			print("\tcurrent_tag_UUID: {}".format(current_tag_UUID))
			print("TAG param is {}".format(tag_param))
			print("TAG UID is {}".format(tag_UID_str))
			ret["topic"] = etp.RFID_CMD_NAME[cmd]
			readall = 1
			ret["payload"] = ",".join('{}'.format(c) for c in [ttype,tag_param,tag_UID_str])
			return ret
		return
	if cmd == etp.CMD_LIST.CMD_GET_TAG_COUNT.value: 
		
		tag_nbr = read_data[7]
		if tag_nbr == 0:
			print('No TAG in the reach of the reader')
		print("{} TAG(s) found in the Reader reach".format(tag_nbr))
		'''
		ret["topic"] = etp.RFID_CMD_NAME[cmd]
		ret["payload"] = str(tag_nbr)
		'''
		return
				
	if cmd == etp.CMD_LIST.CMD_SET_POLLING.value: 
		if SET_POLLING == 1:
			ret["topic"] = "SET_POLLING"
		else:
			ret["topic"] = "RESET_POLLING"
			
		#ret["payload"] = '0'#ACK byte
		return
		
	if cmd == etp.CMD_LIST.CMD_DUMMY_COMMAND.value: 
		dmc_received = 1
		return 
	'''
	ICODE CMDs
	'''
					
	if cmd == etp.CMD_LIST.CMD_ICODE_INVENTORY_START.value or cmd == etp.CMD_LIST.CMD_ICODE_INVENTORY_NEXT.value:  
		'''
		because CMD_GET_TAG_COUNT is limited to 5 tags only, CMD_ICODE_INVENTORY_START/CMD_ICODE_INVENTORY_NEXT
		should be used to detect all the tags in the reach of the antenna
		'''
		tag_UID = read_data[7:15]
		tag_UID_str = ''.join(' {:02X}'.format(c) for c in tag_UID[::-1])
		if current_tag_UUID != tag_UID_str:
			print("\tcurrent_tag_UUID: {}".format(current_tag_UUID))
			current_tag_UUID = tag_UID_str
			readall = 1
			dsfid = read_data[15]
			#More cards flag
			mcf = read_data[16]
			
			print("Inventory read succeed")
			print("\tTag UUID: {}".format(tag_UID_str))
			print("\tTag DSFID: {}".format(dsfid ))
			print("\tTag MCF: {}".format(mcf))
			
			ret["topic"] = etp.RFID_CMD_NAME[cmd]
			ret["payload"] = ",".join('{}'.format(c) for c in [dsfid, mcf,tag_UID_str])
			return ret
			
		readall = 0
		return
	
					
	if cmd == etp.CMD_LIST.CMD_ICODE_READ_BLOCK.value: 
		tag_blk_val = read_data[7:7+cmd_len - 4]# 1byte for ACK, 1 for cmd, 2 for CRC code
		print("Read block succeed, value: {}".format(tag_blk_val))	
		if block_name == "GET_TAG_NAME":
			for c in tag_blk_val:
				tag_name_list.append(c)
		if block_name == "GET_TAG_DATESTART":
			for c in tag_blk_val:
				tag_datestart_list.append(c)
		if block_name == "GET_TAG_DATESTOP":
			for c in tag_blk_val:
				tag_datestop_list.append(c)
		if block_name == "GET_TAG_COMMENTS":
			for c in tag_blk_val:
				tag_comments_list.append(c)
		if block_name == "GET_TAG_EXPNBR":
			for c in tag_blk_val:
				tag_expnbr_list.append(c)
			
		return
	
	if cmd == etp.CMD_LIST.CMD_ICODE_WRITE_BLOCK.value:  
		tag_addr = read_data[7]
		print("Write to TAG memory address {} succeed".format(tag_addr))
		ret["topic"] = block_name
		ret["payload"] = "ACK"
		return ret
		
	if cmd == etp.CMD_LIST.CMD_ICODE_GET_SYSTEM_INFOS.value:  
		sys_infos = read_data[7:7+cmd_len - 4]# 1byte for ACK, 1 for cmd, 2 for CRC code
		sys_infos_str = ' '.join('{:02X}'.format(c) for c in sys_infos) 
		print("Read system infos succeed, value: {}".format(sys_infos_str))
		ret["topic"] = etp.RFID_CMD_NAME[cmd]
		ret["payload"] = sys_infos_str
		return ret
		
	return
	
