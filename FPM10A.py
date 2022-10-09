from machine import UART,Pin
from time import sleep_ms

FINGERPRINT_OK                  =   0x00        #Command execution is complete
FINGERPRINT_PACKETRECIEVEERR    =   0x01        #Error when receiving data package
FINGERPRINT_NOFINGER            =   0x02        #No finger on the sensor
FINGERPRINT_IMAGEFAIL           =   0x03        #Failed to enroll the finger
FINGERPRINT_IMAGEMESS           =   0x06        #Failed to generate character file due to overly disorderly fingerprint image
FINGERPRINT_FEATUREFAIL         =   0x07        #Failed to generate character file due to the lack of character point
                                                #or small fingerprint image
FINGERPRINT_NOMATCH             =   0x08        #Finger doesn't match
FINGERPRINT_NOTFOUND            =   0x09        #Failed to find matching finger
FINGERPRINT_ENROLLMISMATCH      =   0x0A        #Failed to combine the character files
FINGERPRINT_BADLOCATION         =   0x0B        #Addressed PageID is beyond the finger library
FINGERPRINT_DBRANGEFAIL         =   0x0C        #Error when reading template from library or invalid template
FINGERPRINT_UPLOADFEATUREFAIL   =   0x0D        #Error when uploading template
FINGERPRINT_PACKETRESPONSEFAIL  =   0x0E        #Module failed to receive the following data packages
FINGERPRINT_UPLOADFAIL          =   0x0F        #Error when uploading image
FINGERPRINT_DELETEFAIL          =   0x10        #Failed to delete the template
FINGERPRINT_DBCLEARFAIL         =   0x11        #Failed to clear finger library
FINGERPRINT_PASSFAIL            =   0x13        #Find whether the fingerprint passed or failed
FINGERPRINT_INVALIDIMAGE        =   0x15        #Failed to generate image because of lac of valid primary image
FINGERPRINT_FLASHERR            =   0x18        #Error when writing flash
FINGERPRINT_INVALIDREG          =   0x1A        #Invalid register number
FINGERPRINT_ADDRCODE            =   0x20        #Address code
FINGERPRINT_PASSVERIFY          =   0x21        #Verify the fingerprint passed
FINGERPRINT_STARTCODE           =   0xEF01      #Fixed falue of EF01H; High byte transferred first

FINGERPRINT_COMMANDPACKET       =   0x1         #Command packet
FINGERPRINT_DATAPACKET          =   0x2         #Data packet, must follow command packet or acknowledge packet
FINGERPRINT_ACKPACKET           =   0x7         #Acknowledge packet
FINGERPRINT_ENDDATAPACKET       =   0x8         #End of data packet

FINGERPRINT_TIMEOUT             =   0xFF        #Timeout was reached
FINGERPRINT_BADPACKET           =   0xFE        #Bad packet was sent

FINGERPRINT_GETIMAGE            =   0x01        #Collect finger image
FINGERPRINT_IMAGE2TZ            =   0x02        #Generate character file from image
FINGERPRINT_SEARCH              =   0x04        #Search for fingerprint in slot
FINGERPRINT_REGMODEL            =   0x05        #Combine character files and generate template
FINGERPRINT_STORE               =   0x06        #Store template
FINGERPRINT_LOAD                =   0x07        #Read/load template
FINGERPRINT_UPLOAD              =   0x08        #Upload template
FINGERPRINT_DELETE              =   0x0C        #Delete templates
FINGERPRINT_EMPTY               =   0x0D        #Empty library
FINGERPRINT_READSYSPARAM        =   0x0F        #Read system parameters
FINGERPRINT_SETPASSWORD         =   0x12        #Sets passwords
FINGERPRINT_VERIFYPASSWORD      =   0x13        #Verifies the password
FINGERPRINT_HISPEEDSEARCH       =   0x1B        #Asks the sensor to search for a matching fingerprint template to the
                                                #last model generated
FINGERPRINT_TEMPLATECOUNT       =   0x1D        #Read finger template numbers
FINGERPRINT_AURALEDCONFIG       =   0x35        #Aura LED control
FINGERPRINT_LEDON               =   0x50        #Turn on the onboard LED
FINGERPRINT_LEDOFF              =   0x51        #Turn off the onboard LED

FINGERPRINT_LED_BREATHING       =   0x01        #Breathing light
FINGERPRINT_LED_FLASHING        =   0x02        #Flashing light
FINGERPRINT_LED_ON              =   0x03        #Always on
FINGERPRINT_LED_OFF             =   0x04        #Always off
FINGERPRINT_LED_GRADUAL_ON      =   0x05        #Gradually on
FINGERPRINT_LED_GRADUAL_OFF     =   0x06        #Gradually off
FINGERPRINT_LED_RED             =   0x01        #Red LED
FINGERPRINT_LED_BLUE            =   0x02        #Blue LED
FINGERPRINT_LED_PURPLE          =   0x03        #Purple LEDpassword

FINGERPRINT_REG_ADDR_ERROR      =   0x1A        #shows register address error
FINGERPRINT_WRITE_REG           =   0x0E        #Write system register instruction

FINGERPRINT_BAUD_REG_ADDR       =   0x4         #BAUDRATE register address
FINGERPRINT_BAUDRATE_9600       =   0x1         #UART baud 9600
FINGERPRINT_BAUDRATE_19200      =   0x2         #UART baud 19200
FINGERPRINT_BAUDRATE_28800      =   0x3         #UART baud 28800
FINGERPRINT_BAUDRATE_38400      =   0x4         #UART baud 38400
FINGERPRINT_BAUDRATE_48000      =   0x5         #UART baud 48000
FINGERPRINT_BAUDRATE_57600      =   0x6         #UART baud 57600
FINGERPRINT_BAUDRATE_67200      =   0x7         #UART baud 67200
FINGERPRINT_BAUDRATE_76800      =   0x8         #UART baud 76800
FINGERPRINT_BAUDRATE_86400      =   0x9         #UART baud 86400
FINGERPRINT_BAUDRATE_96000      =   0xA         #UART baud 96000
FINGERPRINT_BAUDRATE_105600     =   0xB         #UART baud 105600
FINGERPRINT_BAUDRATE_115200     =   0xC         #UART baud 115200

FINGERPRINT_SECURITY_REG_ADDR   =   0x5         #Security level register address
#The safety level is 1 The highest rate of false recognition , The rejection
#rate is the lowest . The safety level is 5 The lowest tate of false
#recognition, The rejection rate is the highest .
FINGERPRINT_SECURITY_LEVEL_1    =   0X1         #Security level 1
FINGERPRINT_SECURITY_LEVEL_2    =   0X2         #Security level 2
FINGERPRINT_SECURITY_LEVEL_3    =   0X3         #Security level 3
FINGERPRINT_SECURITY_LEVEL_4    =   0X4         #Security level 4
FINGERPRINT_SECURITY_LEVEL_5    =   0X5         #Security level 5

FINGERPRINT_PACKET_REG_ADDR     =   0x6         #Packet size register address
FINGERPRINT_PACKET_SIZE_32      =   0X0         #Packet size is 32 Byte
FINGERPRINT_PACKET_SIZE_64      =   0X1         #Packet size is 64 Byte
FINGERPRINT_PACKET_SIZE_128     =   0X2         #Packet size is 128 Byte
FINGERPRINT_PACKET_SIZE_256     =   0X3         #Packet size is 256 Byte

#define FINGERPRINT_DEBUG

DEFAULTTIMEOUT                  =   1000        #UART reading timeout in milliseconds



class Fingerprint_Packet:
    
    def __init__(self,type,length,data):
        self.start_code=FINGERPRINT_STARTCODE
        self.type=type
        self.length=length
        self.address=[]
        for i in range(4):self.address.append(0xFF)
        self.data=data&0xFF




class FPM10A:

    def __init__(self,password):
        self.serial=UART(2,9600)
        self.password       =   password
        self.Address        =   0xFFFFFFFF
        self.fingerID       =   None
        #The confidence of the fingerFastSearch() match, higher numbers are more
        #confidents
        self.confidence     =   None
        #The number of stored templates in the sensor, set by getTemplateCount()
        self.templateCount  =   None

        self.status_reg     =   0x0             #The status register (set by getParameters)
        self.system_id      =   0x0             #The system identifier (set by getParameters)
        self.capacity       =   64              #The fingerprint capacity (set by getParameters)
        self.security_level =   0               #The security level (set by getParameters)
        self.device_addr    =   0xFFFFFFFF      #The device address (set by getParameters)
        self.packet_len     =   64              #The max packet length (set by getParameters)
        self.baud_rate      =   57600           #The UART baud rate (set by getParameters)
        self.recvPacket     =   []



    def begin(self):
        sleep_ms(1000)
    
    def verifyPassword(self):
        return self.checkPassword()==FINGERPRINT_OK    
    def getParameters(self):pass

    def getImage(self):pass
    def image2Tz(self,slot=1):pass
    def createModel(self):pass

    def emptyDatabase(self):pass
    def storeModel(self,id):pass
    def loadModel(self, id):pass
    def getModel(self):pass
    def deleteModel(self,id):pass
    def fingerFastSearch(self):pass
    def fingerSearch(self,slot=1):pass
    def getTemplateCount(self):pass
    def setPassword(self,password):pass
    def LEDcontrol(self,on):pass
    def LEDcontrol(self,control,speed,coloridx,count=0):pass

    def setBaudRate(self,baudrate):pass
    def setSecurityLevel(self,level):pass
    def setPacketSize(self,size):pass

    def writeStructuredPacket(self,packet):pass
    def getStructuredPacket(self,packet,timeout = DEFAULTTIMEOUT):pass

    def checkPassword(self,void):pass
    def writeRegister(self,regAdd,value):pass





