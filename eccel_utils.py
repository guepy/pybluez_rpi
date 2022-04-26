import eccel_tag_param as etp
import math

def Format_ECCEL_cmd(cmd, arg):
	#read_data template
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
	#read_data template
	#[STX byte(0xF5), cmd_len(2 bytes, LSB first),cmd_len XOR 0xFFFF(2 bytes), ASYNC Byte(0xFE), ECCEL_cmd(1byte), cmd_arg(n bytes),CRC code(2 bytes)]  
	#cmd_len = ASYNC_byte length + ECCEL_cmd length + cmd_arg length + CRC_code length
	# cmd_arg template for cmd = GET_UID_CMD
	# [Tag type(1 byte), TAG param(SAK for MIFARE tags, DSFID for ICODE tags. 1byte), TAG UID bytes(8 bytes max)]
	async_pck = 0
	found = 0
	pck_type = read_data[5]
	if pck_type == etp.CMD_LIST.CMD_ASYNC.value:
		print('ASYNC packet type')
		found = 1
		async_pck = 1
	if pck_type == etp.CMD_LIST.CMD_ACK.value:
		print('ACK packet type')
		found = 1
	if pck_type == etp.CMD_LIST.CMD_ERROR.value:
		print('ECCEL reader failed to execute the sent command')
		return
	if found == 0:
		print('Unknow packet type')
		return
		
	cmd_len = read_data[1] + (read_data[2] >> 8)
	print('cmd len is {}'.format(cmd_len))
	cmd = read_data[6]
	found = 0
	if cmd == etp.CMD_LIST.CMD_GET_UID.value: 
		found = 1
		tag_type = read_data[7]
		tag_param = read_data[8]
		len_UID = cmd_len - 6
		tag_UID = read_data[9:9+(len_UID if len_UID<9 else 8)]
		if tag_type in etp.TAG_TYPE:
			print("TAG type is {}".format(etp.TAG_TYPE[tag_type]))
		else:
			print("TAG type is UNKNOW")
		print("TAG param is {}".format(tag_param))
		tag_UID_str = ''.join(' {:02X}'.format(c) for c in tag_UID)
		print("TAG UID is {}".format(tag_UID_str))
		
	
	if cmd == etp.CMD_LIST.CMD_GET_TAG_COUNT.value:  
		found = 1
		tag_nbr = read_data[7]
		if tag_nbr == 0:
			print('No TAG in the reach of the reader')
			return
		print("{} TAG(s) found in the Reader reach".format(tag_nbr))
	
	if cmd == etp.CMD_LIST.CMD_MFU_READ_PAGE.value:  
		found = 1
		tag_addr = read_data[7]
		print("Read to TAG memory address {} succeed".format(tag_addr))
	
	if cmd == etp.CMD_LIST.CMD_MFU_WRITE_PAGE.value:  
		found = 1
		tag_addr = read_data[7]
		print("Write to TAG memory address {} succeed".format(tag_addr))
	if cmd == etp.CMD_LIST.CMD_SET_POLLING.value:  
		found = 1
		print("Pooling state has been successfully updated")
	if cmd == etp.CMD_LIST.CMD_MFDF_GET_FREEMEM.value:  
		found = 1
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
	return
	
