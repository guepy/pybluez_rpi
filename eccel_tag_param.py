from enum import Enum, unique


TAG_TYPE ={
1:'MIFARE Ultraligth',
2:'MIFARE Ultraligth-C',
3:'MIFARE Classic',
4:'MIFARE Classic 1k',
5:'MIFARE Classic 4k',
6:'MIFARE Plus',
7:'MIFARE Plus 2k',
8:'MIFARE Plus 4k ',
9:'MIFARE Plus 2k sl2',
0xA:'MIFARE Plus 4k sl2',
0xB:'MIFARE Plus 2k sl3',
0xC:'MIFARE Plus 4k sl3',
0xD:'MIFARE Desfire',
0xF:'JCOP',
0x10:'MIFARE Mini',
0x21:'ICODE Sli',
0x22:'ICODE Sli-S',
0x23:'ICODE Sli-L',
0x24:'ICODE Slix',
0x25:'ICODE Slix-S',
0x26:'ICODE Slix-X',
0x27:'ICODE Slix-2',
0x28:'ICODE DNA',
0x42:'BLE Device UID',
0x50:'BLE PIN'
}

CCITTCRCTable = [
0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5,
0x60c6, 0x70e7, 0x8108, 0x9129, 0xa14a, 0xb16b,
0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x0210,
0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c,
0xf3ff, 0xe3de, 0x2462, 0x3443, 0x0420, 0x1401,
0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b,
0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6,
0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738,
0xf7df, 0xe7fe, 0xd79d, 0xc7bc, 0x48c4, 0x58e5,
0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969,
0xa90a, 0xb92b, 0x5af5, 0x4ad4, 0x7ab7, 0x6a96,
0x1a71, 0x0a50, 0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03,
0x0c60, 0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6,
0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb,
0xd10c, 0xc12d, 0xf14e, 0xe16f, 0x1080, 0x00a1,
0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c,
0xe37f, 0xf35e, 0x02b1, 0x1290, 0x22f3, 0x32d2,
0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb, 
0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447,
0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2,
0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827,
0x18c0, 0x08e1, 0x3882, 0x28a3, 0xcb7d, 0xdb5c,
0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0,
0x2ab3, 0x3a92, 0xfd2e, 0xed0f, 0xdd6c, 0xcd4d,
0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba,
0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
0x2e93, 0x3eb2, 0x0ed1, 0x1ef0 ]

@unique 
class CMD_LIST(Enum):
	#General commands
	CMD_ACK = 0x00
	CMD_DUMMY_COMMAND = 0x01
	CMD_GET_TAG_COUNT = 0x02
	CMD_GET_UID = 0x03
	CMD_ACTIVATE_TAG = 0x04
	CMD_HALT = 0x05
	CMD_SET_POLLING = 0x06
	CMD_SET_KEY = 0x07
	CMD_SAVE_KEYS = 0x08
	CMD_SET_NET_CFG = 0x09
	CMD_REBOOT = 0x0A
	CMD_GET_VERSION = 0x0B
	CMD_UART_PASSTHRU = 0x0C

	#mifare clasics commands
	CMD_MF_READ_BLOCK = 0x20
	CMD_MF_WRITE_BLOCK = 0x21
	CMD_MF_READ_VALUE = 0x22
	CMD_MF_WRITE_VALUE = 0x23
	CMD_MF_INCREMENT = 0x24
	CMD_MF_TRANSFER = 0x25
	CMD_MF_RESTORE = 0x26
	CMD_MF_TRANSFER_RESTORE = 0x27

	#mifare ultralight
	CMD_MFU_READ_PAGE = 0x40
	CMD_MFU_WRITE_PAGE = 0x41
	CMD_MFU_GET_VERSION = 0x42
	CMD_MFU_READ_SIG = 0x43
	CMD_MFU_WRITE_SIG = 0x44
	CMD_MFU_LOCK_SIG = 0x45
	CMD_MFU_READ_COUNTER = 0x46
	CMD_MFU_INCREMENT_COUNTER = 0x47
	CMD_MFU_PASSWD_AUTH = 0x48
	CMD_MFUC_AUTHENTICATE = 0x49
	CMD_MFU_CHECKEVENT = 0x4A

	CMD_MFDF_GET_VERSION = 0x60
	CMD_MFDF_SELECT_APP = 0x61
	CMD_MFDF_APP_IDSRROR = 0x62
	CMD_MFDF_FILE_IDS = 0x63
	CMD_MFDF_AUTH = 0x64
	CMD_MFDF_AUTH_ISO = 0x65
	CMD_MFDF_AUTH_AES = 0x66
	CMD_MFDF_CREATE_APP = 0x67
	CMD_MFDF_DELETE_APP = 0x68
	CMD_MFDF_CHANGE_KEY = 0x69
	CMD_MFDF_GET_KEY_SETTINGS = 0x6A
	CMD_MFDF_CHANGE_KEY_SETTINGS = 0x6B
	CMD_MFDF_CREATE_DATA_FILE = 0x6C
	CMD_MFDF_WRITE_DATA = 0x6D
	CMD_MFDF_READ_DATA = 0x6E
	CMD_MFDF_CREATE_VALUE_FILE = 0x6F
	CMD_MFDF_GET_VALUE = 0x70
	CMD_MFDF_CREDIT= 0x71
	CMD_MFDF_LIMITED_CREDIT= 0x72
	CMD_MFDF_DEBIT= 0x73
	CMD_MFDF_CREATE_RECORD_FILE= 0x74
	CMD_MFDF_WRITE_RECORD= 0x75
	CMD_MFDF_READ_RECORD= 0x76
	CMD_MFDF_CLEAR_RECORDS= 0x77
	CMD_MFDF_DELETE_FILE= 0x78
	CMD_MFDF_GET_FREEMEM= 0x79
	CMD_MFDF_FORMAT= 0x7A
	CMD_MFDF_COMMIT_TRANSACTION= 0x7B
	CMD_MFDF_ABORT_TRANSACTION= 0x7C
	#ICODE
	CMD_ICODE_INVENTORY_START = 0x90
	CMD_ICODE_INVENTORY_NEXT = 0x91
	CMD_ICODE_STAY_QUIET = 0x92
	CMD_ICODE_READ_BLOCK = 0x93
	CMD_ICODE_WRITE_BLOCK = 0x94
	CMD_ICODE_LOCK_BLOCK = 0x95
	CMD_ICODE_WRITE_AFI = 0x96
	CMD_ICODE_LOCK_AFI = 0x97
	CMD_ICODE_WRITE_DSFID = 0x98
	CMD_ICODE_LOCK_DSFID = 0x99
	CMD_ICODE_GET_SYSTEM_INFOS = 0x9A
	CMD_ICODE_GET_MULTIPLE_BSS = 0x9B
	CMD_ICODE_PASSWORD_PROTECT_AFI = 0x9C
	CMD_ICODE_READ_EPC = 0x9D
	CMD_ICODE_GET_NXP_SYSTEM_INFOS = 0x9E
	CMD_ICODE_GET_RANDOM_NUMBER = 0x9F
	CMD_ICODE_SET_PASSWORD = 0xA0
	CMD_ICODE_WRITE_PASSWORD = 0xA1
	CMD_ICODE_LOCK_PASSWORD = 0xA2
	CMD_ICODE_PROTECT_PAGE = 0xA3
	CMD_ICODE_LOCK_PAGE_PROTECTION = 0xA4
	CMD_ICODE_GET_MULTIPLE_BPS = 0xA5
	CMD_ICODE_DESTROY = 0xA6
	CMD_ICODE_ENABLE_PRIVACY = 0xA7
	CMD_ICODE_ENABLE_64BIT_PASSWORD = 0xA8
	CMD_ICODE_READ_SIGNATURE = 0xA9
	CMD_ICODE_READ_CONFIG = 0xAA
	CMD_ICODE_WRITE_CONFIG = 0xAB
	CMD_ICODE_PICK_RANDOM_ID = 0xAC

	CMD_ICODE_SET_EAS = 0xAD
	CMD_ICODE_RESET_EAS = 0xAE
	CMD_ICODE_LOCK_EAS = 0xAF
	CMD_ICODE_EAS_ALARM = 0xB0
	CMD_ICODE_PASSWORD_PROTECT_EAS = 0xB1
	CMD_ICODE_WRITE_EASID = 0xB2

	CMD_ASYNC = 0xFE
	CMD_ERROR = 0xFF
 	
def GetCCITTCRC(data):
	if len(data) == 0:
		return
	CRC = 0xFFFF
	for d in data:
		tmp = ((CRC >> 8) ^ (d)) & (0x00FF)
		CRC = (CCITTCRCTable[tmp] ^ (CRC << 8)) & (0xFFFF)
	return CRC