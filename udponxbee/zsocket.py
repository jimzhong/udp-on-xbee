#!/usr/bin/python3
# -*- coding: utf-8 -*-
import socket
from struct import pack, unpack, calcsize

class error(IOError):
    pass

class ZSocket(object):

    SOCKET_PATH = "/tmp/zigbee.sock"
    HDR_FMT = "!QB"
    HDR_LEN = calcsize(HDR_FMT)


    def __init__(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.local_port = None

    def bind(self, local_port=0):
        assert 0 <= local_port <= 0xff
        try:
            self.sock.connect(self.SOCKET_PATH)
            self.sock.send(str(local_port).encode())
            result = self.sock.recv(100)
        except socket.error:
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
        self.sock.send(hdr + data)

    def recvfrom(buffersize=1000):
        '''
        Receive from a bound socket
        return (data, remote_addr, remote_port)
        '''
        if self.local_port is None:
            raise error("bind before recv")
        data = self.sock.recv(buffersize)
        payload = data[hdrlen:]
        a, b = unpack(self.HDR_FMT, data[:self.HDR_LEN])
        return payload, (hexlify(a).decode(), b[0])

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
