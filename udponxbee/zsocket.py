#!/usr/bin/python3
# -*- coding: utf-8 -*-
import socket
from struct import pack, unpack, calcsize
from binascii import hexlify, unhexlify

class error(IOError):
    pass

class ZSocket(object):

    SOCKET_PATH = "/tmp/zigbee.sock"
    HDR_FMT = "!QB"
    HDR_LEN = calcsize(HDR_FMT)


    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.local_port = None

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def bind(self, local_port=0):
        assert 0 <= local_port <= 0xff
        try:
            self.sock.connect(self.SOCKET_PATH)
        except socket.error:
            raise error("daemon is not running?")
        try:
            self.sock.send(str(local_port).encode())
            result = self.sock.recv(100)
        except:
            raise error("bind error")
        if result:
            self.local_port = int(result.decode())
        else:
            raise error("bind error")

    def sendto(self, data, address):
        remote_addr = address[0]
        remote_port = address[1]
        if self.local_port is None:
            # Implicit binding
            self.bind()

        assert 0 <= remote_port <= 0xff
        if isinstance(remote_addr, str):
            remote_addr = int(remote_addr, 16)
        elif not isinstance(remote_addr, int):
            raise TypeError("Invalid address format")

        hdr = pack(self.HDR_FMT, remote_addr, remote_port)
        try:
            self.sock.send(hdr + data)
        except socket.timeout:
            raise error("send timed out")

    def recvfrom(self, buffersize=1000):
        '''
        Receive from a bound socket
        return data, (remote_addr, remote_port)
        '''
        if self.local_port is None:
            raise error("bind before recv")
        try:
            data = self.sock.recv(buffersize)
        except socket.timeout:
            raise error("recv timed out")
        payload = data[self.HDR_LEN:]
        # a, b = unpack(self.HDR_FMT, data[:self.HDR_LEN])
        return payload, (hexlify(data[:8]).decode(), data[8])

    def fileno(self):
        '''
        for select
        '''
        return self.sock.fileno()

    def __hash__(self):
        '''
        for dictionary key
        '''
        return self.sock.__hash__()

    def close(self):
        self.sock.close()
