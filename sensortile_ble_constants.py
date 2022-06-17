


SENSORTILE1_BLE_ADDR='C0:85:23:32:52:36'
SENSORTILE2_BLE_ADDR='F4:24:36:BF:34:E7'


'''
	HARDWARE CHARACTERISTIC SERVICES CHARACTERISTICS 
'''
SENSORTILE_HW_SENSOR_SERVICE_UUID = '00000000-0001-11e1-9ab4-0002a5d5c51b'
#Characteristic for humidity and temp sensors updates
SENSORTILE_ENV_SENSORS_CHAR_UUID ='00140000-0001-11e1-ac36-0002a5d5c51b'
#Characteristic for accelero, gyro, magneto sensors updates
SENSORTILE_ACC_GYRO_MAG_W2ST_CHAR_UUID = '00e00000-0001-11e1-ac36-0002a5d5c51b'
#Characteristitic for onboard LED updates
SENSORTILE_LED_CHAR_UUID = '20000000-0001-11e1-ac36-0002a5d5c51b'
#Characteristitic for microphone input updates
SENSORTILE_MIC_CHAR_UUID = '04000000-0001-11e1-ac36-0002a5d5c51b'
#Characteristitic for quaternion updates
SENSORTILE_QUAT_CHAR_UUID ='00000100-0001-11e1-ac36-0002a5d5c51b'
#Characteristitic for Ecompass updates



SENSORTILE_CONSOLE_SERVICE_UUID = '00000000-000e-11e1-9ab4-0002a5d5c51b'
#characteristic for terminal updates after a read request
SENSORTILE_TERM_CHAR_UUID = '00000001-000e-11e1-ac36-0002a5d5c51b'
#characteristic for std error updates after a read request
SENSORTILE_CSTDERR_CHAR_UUID = '00000002-000e-11e1-ac36-0002a5d5c51b'

SENSORTILE_CONFIG_SERVICE_UUID = '00000000-000f-11e1-9ab4-0002a5d5c51b'
#characteristic to receive notifications answers to a configuration command for accelerometer events
SENSORTILE_CONFIG_W2ST_CHAR_UUID = '00000002-000f-11e1-ac36-0002a5d5c51b'

#Quaternion update size
QUAT_UPDATE_SIZE = 20
