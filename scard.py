import ctypes
lib = ctypes.WinDLL("winscard")


class Scard:
    '''
    Example of order operations:
        scard.establishContext()
        scard.list_readers()
        scard.reader = scard.reader_list[i]
        scard.connect()
        scard.get_status_change() # push atr and card_name(type)
        scard.get_uid() # push uid
        scard.load_key_authentication()
        scard.authenticate_block_with_keyB()
        scard.read() #data in data_block
        scard.write()
        scard.disconnect()
        scard.release_context

        from scard import Scard
        scard = Scard()
        scard.establish_context()
        status, list = scard.list_readers()
        scard.reader = scard.reader_list[1]
        scard.connect()
        scard.get_status_change()
        status, uid = scard.get_uid()
        scard.uid
        position = 0
        block = 1
        scard.load_key_authentication("AAAAAAAAAAAA",position)
        scard.authenticate_block_with_keyB(block, position)
        status, data_block = scard.read_block(block)
        scard.data_block
        value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        scard.write_block(value,block)
        scard.read_block(block)
        scard.disconnect()
        scard.release_context()
    '''
    #lib winscard
    lib = ctypes.WinDLL("winscard")
    #Resource manager handle.
    hContext = ctypes.c_voidp()
    #reader to use
    reader = None    #the card handle.
    reader_list = None
    hCard = ctypes.c_voidp()
    #the chard name, in atr
    #00 00h = Mifare 1k
    #00 02h = Mifare 4k
    #00 03h = Mifare Ultralight
    #00 26h = Mifare Mini
    #F0 04h = Topaz and Jewel
    #F0 11h = Felica 212k
    #F0 12h = Felica 424k
    #__ FFh = Undefined
    card_name = None
    atr = None

    #apdu responde in transmit command
    #https://www.eftlab.com.au/index.php/site-map/knowledge-base/118-apdu-response-list
    sw1 = None
    sw2 = None

    data_block = None




    #CONSTANTS
    SCARD_SCOPE_USER = 0
    SCARD_SCOPE_SYSTEM = 2
    SCARD_SHARE_EXCLUSIVE = 1
    SCARD_SHARE_SHARED = 2
    SCARD_SHARE_DIRECT = 3
    #Power down the card on close
    SCARD_UNPOWER_CARD  =2

    def establish_context(self,scope_mode = 0):
        '''
SCARD_SCOPE_USER   Database operations are performed within the domain of the user.
SCARD_SCOPE_SYSTEM  Database operations are performed within the domain of the system.
                     The calling application must have appropriate access permissions
                     for any database actions.
        return: {
            retval == 0-> ok
            retval !=0-> error
        }
        '''
        lib.SCardEstablishContext.restype = ctypes.c_uint
        retval = lib.SCardEstablishContext(scope_mode, # 0 context is user, 2 system contex
                        None, #reserve to future
                        None, #reserve to future
                        ctypes.pointer(self.hContext) #Returns the resource manager handle.
                        )
        #alternative
        # hContext = ctypes.c_ulong()
        # retval = lib.SCardEstablishContext(0, # 0 context is user, 2 system contex
        #                                         None, None,
        #                                         ctypes.pointer(hContext))
        return retval

    def release_context(self):
        return lib.SCardReleaseContext(self.hContext)

    def list_readers(self):
        '''
        init .reader_list with list of readers
        return status, list
        '''

        pcchReaders = ctypes.c_voidp()

        lib.SCardListReadersA.restype = ctypes.c_uint
        retval = lib.SCardListReadersA(self.hContext,  #Resource manager handle.
            None, # None: list all readers in the system
            None, #list with element
            ctypes.pointer(pcchReaders) # len of card reader list
            )
        if retval !=0:
            return retval, None
        # create buffer with len of reader list
        readerList = (ctypes.c_char * pcchReaders.value)()

        retval = lib.SCardListReadersA(self.hContext,  #Resource manager handle.
            None, # None: list all readers in the system
            ctypes.pointer(readerList), #Multi-string with list of readers
            ctypes.pointer(pcchReaders) # Size of multi-string buffer including NULL's
            )
        if retval !=0:
            return retval, None
        self.reader_list = [x for x in readerList.raw.split('\x00') if x != '']

        return retval, self.reader_list

    def connect(self, share_mode = 2):
        '''
SCARD_SHARE_SHARED  This application is willing to share the card with other applications.
SCARD_SHARE_EXCLUSIVE  This application is not willing to share the card with other applications.
SCARD_SHARE_DIRECT  This application is allocating the reader for its private use, and will be controlling it directly. No other applications are allowed access to it.
        '''

        activeprotocol = ctypes.c_voidp()
        self.atr = None
        self.card_name = None

        lib.SCardConnectA.restype = ctypes.c_uint
        retval = lib.SCardConnectA(self.hContext,#Resource manager handle.
            self.reader, # Reader name.
            share_mode, #Share Mode, SCARD_SHARE_SHARED
            0x2, #Preferred protocols, 0x2 ->SCARD_PROTOCOL_T1
            ctypes.pointer(self.hCard), # Returns the card handle.
            ctypes.pointer(activeprotocol) # Active protocol.
            )

        return retval

    def disconnect(self):
        '''
        return:
            retval == 0 ->ok
            retval !=0 ->error
        '''
        lib.SCardDisconnect.restype = ctypes.c_uint
        retval = lib.SCardDisconnect(self.hCard, # the card handle.
                Scard.SCARD_UNPOWER_CARD #Action to take on the card in the connected reader on close.
            )
        return retval


    def get_status_change(self):
        readerState = SCARD_READERSTATE()
        readerState.szReader = self.reader
        readerState.dwCurrentState = 0x00000000 #
        readerState.dwEventState = 0x00000000
        ReaderCount = 1

        lib.SCardGetStatusChangeA.restype = ctypes.c_uint
        retval = lib.SCardGetStatusChangeA(self.hContext, #// Resource manager handle
                0, #Max. amount of time (in milliseconds) to wait for an action.
                ctypes.pointer(readerState), #readerState
                ReaderCount #The number of elements in the rgReaderStates array.
                )
        if retval == 0 :
            self.atr = ''.join('{0:02X}'.format(i)+' ' for i in readerState.rgbAtr[0:readerState.cbAtr])[0:-1]
            self.card_name = ['{0:02X}'.format(readerState.rgbAtr[readerState.cbAtr - 0x7]),
                             '{0:02X}'.format(readerState.rgbAtr[readerState.cbAtr - 0x6])]

        return retval

    def get_uid(self):
        '''
        return: status, uid
        status:
            0 ->ok
            -1 -> error in atr command, object.sw1 object.sw2 code error
        '''
        sioreq = SCARD_IO_REQUEST()
        sioreq.dwProtocol = 0x2
        sioreq.cbPciLength = 8
        rioreq = SCARD_IO_REQUEST()
        rioreq.dwProtocol = 0x2
        rioreq.cbPciLength = 8

        bcla = 0xFF
        bins = 0xCA
        bp1 = 0x0
        bp2 = 0x0
        leng = 0x0
        sendBufferLen = ctypes.c_int()
        sendBufferLen = 0x5

        sendBuffer = (ctypes.c_ubyte*256)()
        receiveBuffer = (ctypes.c_ubyte*256)()
        receiveBufferLen = ctypes.c_int(len(receiveBuffer))
        sendBuffer[0] = bcla
        sendBuffer[1] = bins
        sendBuffer[2] = bp1
        sendBuffer[3] = bp2
        sendBuffer[4] = leng

        lib.SCardTransmit.restype = ctypes.c_uint
        retval = lib.SCardTransmit(
            self.hCard,# Card handle.
            ctypes.pointer(sioreq), #Pointer to the send protocol header.
            ctypes.pointer(sendBuffer), #Send buffer.
            sendBufferLen, #Send buffer length.
            ctypes.pointer(rioreq), #Pointer to the rec. protocol header.
            ctypes.pointer(receiveBuffer), #Receive buffer.
            ctypes.pointer(receiveBufferLen) #Receive buffer length.
            )

        if retval == 0:
            self.sw1 = receiveBuffer[receiveBufferLen.value - 2]
            self.sw2 = receiveBuffer[receiveBufferLen.value -1]
            if self.sw1==0x90 and self.sw2==0:
                self.uid = ''.join('{0:02X}'.format(i) for i in receiveBuffer[0:receiveBufferLen.value-2])
            else: # error in transmit
                return -1, None
        return retval, self.uid

    def load_key_authentication(self,key,position = None):
        '''
        @key, string in hex format of leng 12 (6bytes)
        @position to store key(0..31), None if store in memoria volatile.
        '''
        sioreq = SCARD_IO_REQUEST()
        sioreq.dwProtocol = 0x2
        sioreq.cbPciLength = 8
        rioreq = SCARD_IO_REQUEST()
        rioreq.dwProtocol = 0x2
        rioreq.cbPciLength = 8

        key_byte =  bytearray.fromhex(key)

        sendBuffer = (ctypes.c_ubyte*256)()
        bcla = 0xFF
        bins = 0x82 #instrucction
        if position!=None:
            bp1 = 0x20 #non_volatile
            bp2 = position
        else:
            bp1 = 0x00 # memory volatile
            bp2 = 0x20
        leng = len(key_byte) #must be 0x06
        sendBuffer[0] = bcla
        sendBuffer[1] = bins
        sendBuffer[2] = bp1
        sendBuffer[3] = bp2
        sendBuffer[4] = leng
        for i, value in enumerate(key_byte):
            sendBuffer[5+i] = value

        sendBufferLen = ctypes.c_int()
        sendBufferLen = 0xB
        receiveBuffer = (ctypes.c_ubyte*256)()
        receiveBufferLen = ctypes.c_int(len(receiveBuffer))

        lib.SCardTransmit.restype = ctypes.c_uint
        retval = lib.SCardTransmit(
            self.hCard,# Card handle.
            ctypes.pointer(sioreq), #Pointer to the send protocol header.
            ctypes.pointer(sendBuffer), #Send buffer.
            sendBufferLen, #Send buffer length.
            ctypes.pointer(rioreq), #Pointer to the rec. protocol header.
            ctypes.pointer(receiveBuffer), #Receive buffer.
            ctypes.pointer(receiveBufferLen) #Receive buffer length.
        )

        if retval == 0:
            self.sw1 = receiveBuffer[receiveBufferLen.value - 2]
            self.sw2 = receiveBuffer[receiveBufferLen.value -1]
            if self.sw1==0x90 and self.sw2==0:
                None
            else: # error in transmit
                return -1
        return retval


    def _authenticate_block(self,block,keyA, position = None):
        '''
        authenticate block with keyA or keyB
        @block to authenticate
        @keyA true if authenticate keyA, false authenticate KeyB
        @position the key (0..31), None key in volatile memory
        '''
        sioreq = SCARD_IO_REQUEST()
        sioreq.dwProtocol = 0x2
        sioreq.cbPciLength = 8
        rioreq = SCARD_IO_REQUEST()
        rioreq.dwProtocol = 0x2
        rioreq.cbPciLength = 8
        sendBuffer = (ctypes.c_ubyte*256)()

        bcla = 0xFF
        bins = 0x86
        bp1 = 0x0
        bp2 = 0x0
        leng = 0x5

        sendBuffer[0] = bcla
        sendBuffer[1] = bins
        sendBuffer[2] = bp1
        sendBuffer[3] = bp2
        sendBuffer[4] = leng

        sendBuffer[5] = 0x1 #Version
        sendBuffer[6] = 0x0 #Address MSB
        sendBuffer[7] = block

        if keyA :
            sendBuffer[8] = 0x60
        else:
            sendBuffer[8] = 0x61

        if position == None:
            sendBuffer[9] = 0x20 #memory volatile
        else: # valid position
            sendBuffer[9] = position

        sendBufferLen = 0xA
        receiveBuffer = (ctypes.c_ubyte*256)()
        receiveBufferLen = ctypes.c_int(len(receiveBuffer))

        lib.SCardTransmit.restype = ctypes.c_uint
        retval = lib.SCardTransmit(
            self.hCard,# Card handle.
            ctypes.pointer(sioreq), #Pointer to the send protocol header.
            ctypes.pointer(sendBuffer), #Send buffer.
            sendBufferLen, #Send buffer length.
            ctypes.pointer(rioreq), #Pointer to the rec. protocol header.
            ctypes.pointer(receiveBuffer), #Receive buffer.
            ctypes.pointer(receiveBufferLen) #Receive buffer length.
        )

        if retval == 0:
            self.sw1 = receiveBuffer[receiveBufferLen.value - 2]
            self.sw2 = receiveBuffer[receiveBufferLen.value -1]
            if self.sw1==0x90 and self.sw2==0:
                None
            else: # error in transmit
                return -1
        return retval

    def authenticate_block_with_keyA(self, block, position =None):
        '''
        authenticate block with keyA
        @block to authenticate
        @position the key (0..31), None key in volatile memory
        '''
        return self._authenticate_block(block, True, position)

    def authenticate_block_with_keyB(self, block, position =None):
        '''
        authenticate block with keyB
        @block to authenticate
        @position the key (0..31), None key in volatile memory
        '''
        return self._authenticate_block(block, False, position)


    def read_block(self,block):
        '''
        read block, I sussposed that read mifare classic (16bytes by block)
        store in object.data_block 16bytes read in format hex
        return: status, block read
        '''
        sioreq = SCARD_IO_REQUEST()
        sioreq.dwProtocol = 0x2
        sioreq.cbPciLength = 8
        rioreq = SCARD_IO_REQUEST()
        rioreq.dwProtocol = 0x2
        rioreq.cbPciLength = 8
        sendBuffer = (ctypes.c_ubyte*256)()

        bcla = 0xFF
        bins = 0xB0
        bp1 = 0x0
        bp2 = block # block
        leng = 16 #number bytes to read

        sendBuffer[0] = bcla
        sendBuffer[1] = bins
        sendBuffer[2] = bp1
        sendBuffer[3] = bp2
        sendBuffer[4] = leng
        sendBufferLen = 0x5
        receiveBuffer = (ctypes.c_ubyte*256)()
        receiveBufferLen = ctypes.c_int(len(receiveBuffer))

        lib.SCardTransmit.restype = ctypes.c_uint
        retval = lib.SCardTransmit(
            self.hCard,# Card handle.
            ctypes.pointer(sioreq), #Pointer to the send protocol header.
            ctypes.pointer(sendBuffer), #Send buffer.
            sendBufferLen, #Send buffer length.
            ctypes.pointer(rioreq), #Pointer to the rec. protocol header.
            ctypes.pointer(receiveBuffer), #Receive buffer.
            ctypes.pointer(receiveBufferLen) #Receive buffer length.
        )

        if retval == 0:
            self.sw1 = receiveBuffer[receiveBufferLen.value - 2]
            self.sw2 = receiveBuffer[receiveBufferLen.value -1]
            if self.sw1==0x90 and self.sw2==0:
                None
            else: # error in transmit
                return -1, None
        self.data_block = ''.join('{0:02X}'.format(i) for i in receiveBuffer[0:receiveBufferLen.value-2])
        return retval, self.data_block

    def write_block(self,value,block):
        '''
        write block, I sussposed that write mifare classic (16bytes by block)
        @value, string in hex format of leng 32 (16bytes)
        @block of block to write
        '''
        sioreq = SCARD_IO_REQUEST()
        sioreq.dwProtocol = 0x2
        sioreq.cbPciLength = 8
        rioreq = SCARD_IO_REQUEST()
        rioreq.dwProtocol = 0x2
        rioreq.cbPciLength = 8
        sendBuffer = (ctypes.c_ubyte*256)()

        bcla = 0xFF
        bins = 0xD6
        bp1 = 0x0
        bp2 = block # block
        leng = 16 #number bytes to write
        sendBuffer = (ctypes.c_ubyte*256)()
        sendBuffer[0] = bcla
        sendBuffer[1] = bins
        sendBuffer[2] = bp1
        sendBuffer[3] = bp2
        sendBuffer[4] = leng

        aux =  bytearray.fromhex(value)
        for i, x in enumerate(aux):
            sendBuffer[5+i] = x

        sendBufferLen = 0x15 #5+16 = 21 = 0x15
        receiveBuffer = (ctypes.c_ubyte*256)()
        receiveBufferLen = ctypes.c_int(len(receiveBuffer))

        lib.SCardTransmit.restype = ctypes.c_uint
        retval = lib.SCardTransmit(
            self.hCard,# Card handle.
            ctypes.pointer(sioreq), #Pointer to the send protocol header.
            ctypes.pointer(sendBuffer), #Send buffer.
            sendBufferLen, #Send buffer length.
            ctypes.pointer(rioreq), #Pointer to the rec. protocol header.
            ctypes.pointer(receiveBuffer), #Receive buffer.
            ctypes.pointer(receiveBufferLen) #Receive buffer length.
        )

        if retval == 0:
            self.sw1 = receiveBuffer[receiveBufferLen.value - 2]
            self.sw2 = receiveBuffer[receiveBufferLen.value -1]
            if self.sw1==0x90 and self.sw2==0:
                None
            else: # error in transmit
                return -1
        return retval

    def is_mifare_classic_4k(self):
        return self.card_name[0] == '00' and self.card_name[1] == '02'

    def error(self):
        return '{0:02X}'.format(self.sw1)+" "+'{0:02X}'.format(self.sw2)

class SCARD_READERSTATE(ctypes.Structure):
    _fields_ = [("szReader", ctypes.c_char_p),
                ("pvUserData", ctypes.c_void_p),
                ("dwCurrentState", ctypes.c_int),
                ("dwEventState", ctypes.c_int),
                ("cbAtr", ctypes.c_int), #ATR Length, usually MAX_ATR_SIZE
                ("rgbAtr", ctypes.c_ubyte * 36)
                ]

class SCARD_IO_REQUEST(ctypes.Structure):
    _fields_ = [("dwProtocol", ctypes.c_uint), # Protocol in use.
                ("cbPciLength", ctypes.c_uint) # Length, in bytes, of the SCARD_IO_REQUEST structure plus any following PCI-specific information.
                ]