import eccel_tag_param as etp
import math

ret = {
"topic": "",
"payload":"",
"name":""
}
	
def Format_ECCEL_cmd(cmd, arg):
	#send_data template
	#[STX byte(0xF5), cmd_len(2 bytes, LSB first),cmd_len XOR 0xFFFF(2 bytes), ASYNC Byte(0xFE), ECCEL_cmd(1byte), cmd_arg(n bytes),CRC code(2 bytes)]  
	#cmd_len = ASYNC_byte length + ECCEL_cmd length + cmd_arg length + CRC_code length
	# cmd_arg template for cmd = GET_UID_CMD
	# [Tag type(1 byte), TAG param(SAK for MIFARE tags, DSFID for ICODE tags. 1byte), TAG UID bytes(8 bytes max)]
	to_send = list()
	to_send.append(0xF5)
	data = [cmd & 0xFF]
	arg_len = len(arg)
	if arg_len == 0:
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
		cmd_len = 1 + 2
		to_send.append(cmd & 0xFF)	

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

def Process_ECCEL_read_data(read_data):
	global ret
	#send_data template
	#[STX byte(0xF5), cmd_len(2 bytes, LSB first),cmd_len XOR 0xFFFF(2 bytes), ASYNC Byte(0xFE), ECCEL_cmd(1byte), cmd_arg(n bytes),CRC code(2 bytes)]  
	#cmd_len = ASYNC_byte length + ECCEL_cmd length + cmd_arg length + CRC_code length
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
	if pck_type == etp.CMD_LIST.CMD_ERROR.value:
		print('ECCEL reader failed to execute the sent command')
		ret["topic"] = "PCK_TYPE"
		ret["payload"] = "ERR"
		return ret
	if found == 0:
		print('Unknow packet type')
		ret["topic"] = "PCK_TYPE"
		ret["payload"] = "UNKNOW"
		return ret
		
	cmd_len = read_data[1] + (read_data[2] >> 8)
	print('cmd len is {}'.format(cmd_len))
	cmd = read_data[6]
	
	'''
	General commands
	'''
	if cmd == etp.CMD_LIST.CMD_GET_UID.value: 
		tag_type = read_data[7]
		tag_param = read_data[8]
		len_UID = cmd_len - 3
		tag_UID = read_data[9:9+(len_UID if len_UID<9 else 8)]
		ttype = ""
		if tag_type in etp.TAG_TYPE:
			ttype = etp.TAG_TYPE[tag_type]
			print("TAG type is {}".format(ttype))
		else:
			ttype = "UNKNOW"
			print("TAG type is UNKNOW")
		print("TAG param is {}".format(tag_param))
		tag_UID_str = ''.join(' {:02X}'.format(c) for c in tag_UID)
		print("TAG UID is {}".format(tag_UID_str))
		ret["topic"] = "GET_TAG_INFOS"
		ret["payload"] = ",".join('{}'.format(c) for c in [ttype,tag_param,tag_UID_str])
		return ret
		
	if cmd == etp.CMD_LIST.CMD_GET_TAG_COUNT.value: 
		tag_nbr = read_data[7]
		if tag_nbr == 0:
			print('No TAG in the reach of the reader')
		print("{} TAG(s) found in the Reader reach".format(tag_nbr))
		ret["topic"] = "GET_TAG_CNT"
		ret["payload"] = str(tag_nbr)
		return ret
				
	if cmd == etp.CMD_LIST.CMD_SET_POLLING.value: 
		ret["topic"] = "SET_POLLING"
		ret["payload"] = '0'#ACK byte
		return ret
	'''
	ICODE CMDs
	'''
					
	if cmd == etp.CMD_LIST.CMD_ICODE_INVENTORY_START.value or cmd == etp.CMD_LIST.CMD_ICODE_INVENTORY_NEXT.value:  
		'''
		because CMD_GET_TAG_COUNT is limited to 5 tags only, CMD_ICODE_INVENTORY_START/CMD_ICODE_INVENTORY_NEXT
		should be used to detect all the tags in the reach of the antenna
		'''
		
		tag_UID = read_data[7:14]
		tag_UID_str = ''.join(' {:02X}'.format(c) for c in tag_UID)
		dsfid = read_data[15]
		#More cards flag
		mcf = read_data[16]
		print("Inventory read succeed")
		print("\tTag UUID: {}".format(tag_UID_str))
		print("\tTag DSFID: {}".format(dsfid ))
		print("\tTag MCF: {}".format(mcf))
		if cmd == etp.CMD_LIST.CMD_ICODE_INVENTORY_START.value:
			ret["topic"] = "TAG_INVENTORY_START"
		else:
			ret["topic"] = "TAG_INVENTORY_NEXT"
		ret["payload"] = ",".join('{}'.format(c) for c in [tag_UID_str, dsfid, mcf])
		return ret
	
					
	if cmd == etp.CMD_LIST.CMD_ICODE_READ_BLOCK.value: 
		tag_blk_val = read_data[7:cmd_len - 3]
		tag_blk_val_str = ' '.join('{:02X}'.format(c) for c in tag_blk_val) 
		print("Read block succeed, value: {}".format(tag_blk_val_str))
		ret["topic"] = "READ_BLOCK"
		ret["payload"] = tag_blk_val_str
		return ret
	
	if cmd == etp.CMD_LIST.CMD_ICODE_WRITE_BLOCK.value:  
		tag_addr = read_data[7]
		print("Write to TAG memory address {} succeed".format(tag_addr))
		ret["topic"] = "WRITE_BLOCK"
		ret["payload"] = "ACK"
		return ret
		
	if cmd == etp.CMD_LIST.CMD_ICODE_GET_SYSTEM_INFOS.value:  
		sys_infos = read_data[7:cmd_len - 3]
		sys_infos_str = ' '.join('{:02X}'.format(c) for c in sys_infos) 
		print("Read system infos succeed, value: {}".format(sys_infos_str))
		ret["topic"] = "SYS_INFOS"
		ret["payload"] = sys_infos_str
		return ret
		
		'''
	if cmd == etp.CMD_LIST.CMD_MFU_READ_PAGE.value: 
		tag_addr = read_data[7]
		print("Read to TAG memory address {} succeed".format(tag_addr))
	
	if cmd == etp.CMD_LIST.CMD_MFU_WRITE_PAGE.value:  
		tag_addr = read_data[7]
		print("Write to TAG memory address {} succeed".format(tag_addr))
	if cmd == etp.CMD_LIST.CMD_SET_POLLING.value:  
		found = 1
		print("Pooling state has been successfully updated")
	if cmd == etp.CMD_LIST.CMD_MFDF_GET_FREEMEM.value:  
		free_mem = read_data[7] + (read_data[8] << 8) + (read_data[9] << 16) + (read_data[10] << 24)
		if free_mem > math.pow(2,30):
			print("free memory on the activated tag is {} Go".format(free_mem/math.pow(2,30)))
			return
		if free_mem > math.pow(2,20):
			print("free memory on the activated tag is {} Mo".format(free_mem/math.pow(2,20)))
			return
		if free_mem > math.pow(2,10):
			print("free memory on the activated tag is {} Ko".format(free_mem/math.pow(2,10)))
			return
		print("free memory on the activated tag is {} octets".format(free_mem))
	if cmd == etp.CMD_LIST.CMD_MFDF_APP_IDSRROR.value:  
		app_id_nbr = cmd_len - 3
		app_ids = read_data[7:-2] 
		app_id_list = ''.join(' {:02X}'.format(i) for i in app_ids)
		print("The read TAG contains an APP with ID {}".format(app_id_list))
	'''
	return
	
