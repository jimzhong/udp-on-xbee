from struct import pack, unpack, calcsize
from binascii import hexlify, unhexlify
from enum import Enum
import logging

START_DELIMITER = 0x7E

class XBeeOutFrame(object):

    def __bytes__(self):
        raise NotImplementedError("Subclass should implement this method")

    @staticmethod
    def calc_checksum(partial_frame):
        '''
        partial_frame do not contain first 3 bytes and the last byte of checksum
        '''
        return pack("!B", 0xff - (sum(partial_frame) & 0xff))


class XBeeInFrame(object):

    AT_RESPONSE = 0x88
    MODEM_STATUS = 0x8A
    TX_STATUS = 0x8B
    RX_PACKET = 0x90


    @staticmethod
    def verify_frame(frame):
        val = sum(frame[3:]) & 0xff
        return val == 0xff


    @classmethod
    def from_bytes(cls, data):
        decoder = {
            cls.AT_RESPONSE: XBeeATResponse,
            cls.MODEM_STATUS: XBeeModemStatus,
            cls.TX_STATUS: XBeeTXStatus,
            cls.RX_PACKET: XBeeRXPacket,
        }
        if data[0] != START_DELIMITER:
            raise ValueError("Delimiter is incorrect.")
        if cls.verify_frame(data) == False:
            raise ValueError("Frame is corrupted.")
        if data[3] in decoder:
            return decoder[data[3]](data)
        else:
            raise ValueError("Unknown frame of type 0x{:x}".format(data[3]))


class XBeeATResponse(XBeeInFrame):

    def __init__(self, data):
        '''
        value is a bytearray
        '''
        assert data[3] == self.AT_RESPONSE
        atcmd = data[5:7]
        atdata = data[8:-1]
        self.frame_id = data[4]
        self.status = data[7]
        self.key = atcmd.decode()
        self.value = atdata

    def __str__(self):
        return "ATResponse: {} = {}".format(self.key, self.value)


class XBeeRXPacket(XBeeInFrame):

    def __init__(self, frame):
        assert frame[3] == self.RX_PACKET
        self.addr64 = int.from_bytes(frame[4:12], 'big')
        self.addr16 = int.from_bytes(frame[12:14], 'big')
        self.data = frame[15:-1]

    def __str__(self):
        return "RXPacket from {:x} of {} bytes".format(self.addr64, len(self.data))


class XBeeTXStatus(XBeeInFrame):

    def __init__(self, frame):
        assert frame[3] == self.TX_STATUS
        self.frame_id = frame[4]
        self.addr16 = int.from_bytes(frame[5:7], 'big')
        self.delivery_status = frame[8]
        self.discovery_status = frame[9]

    def __str__(self):
        return "TXStatus: delivery={}, discovery={}".format(self.delivery_status, self.discovery_status)


class XBeeModemStatus(XBeeInFrame):

    class Status(Enum):
        HW_RESET= 0
        WDT_RESET = 1
        JOIN = 2
        DISASSOC = 3
        COORDINATOR_START = 6
        KEY_UPDATE = 7

    def __init__(self, frame):
        assert frame[3] == self.MODEM_STATUS
        self.status = self.Status(frame[4])

    def __str__(self):
        return "ModemStatus: {}".format(self.status)


class XBeeTXRequest(XBeeOutFrame):

    TX_REQUEST_CMD = 0x10
    TX_REQ_HEADER_FMT = "!BBQHBB"
    TX_REQ_HEADER_SIZE = calcsize(TX_REQ_HEADER_FMT)

    def __init__(self, addr64, *data):
        self.data = b''.join(data)
        if isinstance(addr64, str):
            self.addr64 = int(addr64, 16)
        elif isinstance(addr64, int):
            self.addr64 = addr64
        else:
            raise TypeError("Addr64 should be string or int")

    def __bytes__(self):
        length = len(self.data) + self.TX_REQ_HEADER_SIZE
        ohdr = pack("!BH", 0x7e, length)
        ihdr = pack(self.TX_REQ_HEADER_FMT, self.TX_REQUEST_CMD, 0, self.addr64, 0xfffe, 0, 0)
        checksum = 0xff - ((sum(ihdr) + sum(self.data)) & 0xff)
        checksum = pack("!B", checksum)
        return b"".join([ohdr, ihdr, self.data, checksum])

    def __str__(self):
        return "TXRequest to {:x} of {} bytes".format(self.addr64, len(self.data))


class XBeeATRequest(XBeeOutFrame):

    AT_REQUEST_CMD = 0x08
    AT_HEADER_FMT = "!BB2s"
    AT_HEADER_SIZE = calcsize(AT_HEADER_FMT)

    def __init__(self, key, value=b'', frame_id=1):
        '''
        value should be a hex string
        '''
        self.key = key
        self.value = value
        self.frame_id = frame_id

    def __bytes__(self):
        length = len(self.value) + self.AT_HEADER_SIZE
        ohdr = pack("!BH", START_DELIMITER, length)
        ihdr = pack(self.AT_HEADER_FMT, self.AT_REQUEST_CMD, self.frame_id, self.key.encode())
        checksum = 0xff - ((sum(ihdr) + sum(self.value)) & 0xff)
        checksum = pack("!B", checksum)
        return b"".join([ohdr, ihdr, self.value, checksum])

    def __str__(self):
        return ("ATRequest {} = {}".format(self.key, self.value))


if __name__ == "__main__":
    frame = XBeeTXRequest("eeeeee", b'TxData1B')
    frame = XBeeATRequest("NI")
    frame = XBeeInFrame.from_bytes(unhexlify("7e00028a066f"))
    # frame = XBeeInFrame.from_bytes(unhexlify("7e00058801424400f0"))
    # frame = XBeeInFrame.from_bytes(unhexlify("7e0011900013a20040522baa7d84015278446174610d"))
    print(frame)
