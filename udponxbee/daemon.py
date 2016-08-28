import socket
import serial
import select
import random
import logging
import os
import json
from struct import pack, unpack, calcsize
from queue import Queue, Empty
from binascii import hexlify, unhexlify
from .frame import *

logging.basicConfig(level=logging.DEBUG)

class Connection(object):

    def __init__(self, sock, local_port):
        self.sock = sock
        self.local_port = local_port

    def deliver(self, data, remote_addr, remote_port):
        hdr = pack("!QB", remote_addr, remote_port)
        self.sock.send(hdr+data)


class Daemon(object):

    def __init__(self, serial_port="/dev/ttyUSB0", baudrate=115200,
                 server_path="/tmp/zigbee.sock", info_path="/tmp/zigbee.info.sock"):

        self.ser = serial.Serial(serial_port, baudrate, timeout=0)
        try:
            self.get_xbee_info()
        except Exception as e:
            logging.exception(e)
            raise IOError("IOError with XBee")

        logging.info(self.info)
        self.server_sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.info_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        for p in (server_path, info_path):
            try:
                os.unlink(p)
            except FileNotFoundError:
                pass

        self.info_sock.bind(info_path)
        self.server_sock.bind(server_path)

    def get_xbee_info(self):
        self.info = {
            "tx_total": 0,
            "rx_total": 0,
            "tx_error": 0,
            }
        for cmd in ['NI', 'SH', 'SL', 'ID', '%V', 'OP']:
            frame = XBeeATRequest(cmd)
            self.ser.write(bytes(frame))
            self.ser.flush()
            inframe = XBeeInFrame.from_bytes(self.read_full_frame())
            if isinstance(inframe, XBeeATResponse):
                self.info[inframe.key] = hexlify(inframe.value).decode()
            else:
                logging.error(inframe)

    def read_full_frame(self, retry=100000):
        '''
        Read a full frame from self.ser

        blocking reading, only use for initializing
        '''
        buf = bytearray()
        length = 1000
        for _ in range(retry):
            data = self.ser.read(1000)
            if not data:
                continue
            buf.extend(data)
            if len(buf) > 3:
                assert buf[0] == 0x7E
                length = buf[1] * 256 + buf[2]
            if len(buf) == length + 4:
                break
        else:
            raise IOError("Did not get a complete frame.")
        return buf


    def stop(self):
        self.running = False
        self.ser.close()
        self.server_sock.close()

    def run(self):
        self.serial_in = bytearray()    #Serial input buffer
        self.frames_in = Queue()    #XBee input frames
        self.frames_out = Queue()   #XBee output frames
        self.frame_id = 1   #for matching TXStatus with TXRequest

        self.server_sock.listen(10)
        self.info_sock.listen(2)
        self.running = True
        self.rlist = [self.ser, self.server_sock, self.info_sock]
        self.port2conn = {}
        self.sock2conn = {}

        while self.running:
            logging.debug("Action connections: {}".format(len(self.port2conn)))
            try:
                readable, _, _ = select.select(self.rlist, [], [], 5)
            except select.error as e:
                logging.exception(e)

            for sock in readable:
                if sock == self.info_sock:
                    logging.debug("accept new unix connection on info sock")
                    conn, addr = self.info_sock.accept()
                    conn.send(json.dumps(self.info).encode())
                    conn.close()
                elif sock == self.server_sock:
                    client, addr = self.server_sock.accept()
                    logging.debug("accept new unix connection on server sock")
                    self.rlist.append(client)
                elif sock == self.ser:
                    self.handle_xbee_in()
                else:
                    # sock is from client
                    self.handle_client(sock)

            self.handle_frames_in()
            self.handle_xbee_out()


    def handle_frames_in(self):
        while True:
            try:
                frame = self.frames_in.get_nowait()
                if isinstance(frame, XBeeRXPacket):
                    src_port = frame.data[0]
                    dest_port = frame.data[1]
                    logging.info("received datagram to port {} from {:x}:{}".format(dest_port, frame.addr64, src_port))
                    if dest_port in self.port2conn:
                        self.port2conn[dest_port].deliver(data[2:], frame.addr64, src_port)
                    else:
                        logging.warning("Could not find port {}".format(dest_port))
                elif isinstance(frame, XBeeTXStatus):
                    if frame.delivery_status != frame.DeliveryStatus.SUCCESS:
                        self.info['tx_error'] += 1
                else:
                    logging.info(str(frame))
            except Empty:
                break


    def find_available_port(self):

        ports = set(range(1, 255))
        busy_ports = set(self.port2conn.keys())
        ports.difference_update(busy_ports)
        if len(ports) == 0:
            return 0
        return random.choice(tuple(ports))

    def close_and_remove(self, sock):
        try:
            self.rlist.remove(sock)
        except ValueError:
            logging.warning("removing non-existent socket from rlist")
        sock.close()


    def handle_client(self, sock):
        if sock in self.sock2conn:
            # a already bound socket
            data = sock.recv(1024)
            conn = self.sock2conn[sock]
            if data:
                addr64, remote_port = unpack("!QB", data[:calcsize("!QB")])
                logging.info("sending new datagram from port {} to {:x}:{}".format(conn.local_port, addr64, remote_port))
                hdr = pack("!BB", conn.local_port, remote_port)
                payload = data[calcsize("!QB"):]
                frame = XBeeTXRequest(addr64, hdr, payload, frame_id=self.frame_id)
                self.frame_id += 1
                if self.frame_id > 0xff:
                    self.frame_id = 1
                self.frames_out.put(frame)
            else:
                self.close_and_remove(sock)
                self.sock2conn.pop(sock)
                self.port2conn.pop(conn.local_port)
                logging.info("port {} closed".format(conn.local_port))
                del conn
        else:
            logging.debug("new sock: {}".format(sock))
            try:
                bind_port = int(sock.recv(20).decode())
            except ValueError:
                logging.error("bind error, close socket")
                self.close_and_remove(sock)
                return
            logging.debug("request to bind port {}".format(bind_port))

            if bind_port == 0:
                bind_port = self.find_available_port()
            if bind_port == 0:
                logging.error("ports full, drop connection")
                self.close_and_remove(sock)
                return

            if bind_port in self.port2conn:
                logging.error("port {} is in use, close socket".format(bind_port))
                self.close_and_remove(sock)
                return

            logging.info("New connection on port {}".format(bind_port))
            conn = Connection(sock, bind_port)
            self.sock2conn[sock] = conn
            self.port2conn[bind_port] = conn
            sock.send(str(bind_port).encode())


    def handle_xbee_in(self):
        '''
        Extract frames from serial, put to self.frames_in
        '''
        data = self.ser.read(1000)
        logging.debug("[SERIAL] {} bytes read".format(len(data)))
        self.serial_in.extend(data)
        while True:
            if not self.serial_in:
                return
            assert self.serial_in[0] == START_DELIMITER
            try:
                length = self.serial_in[1] * 256 + self.serial_in[2]
                if len(self.serial_in) >= length+4:
                    logging.debug("[SERIAL] found new frame of length {}".format(length))
                    self.info['rx_total'] += 1
                    frame = self.serial_in[:length+4]
                    self.frames_in.put(XBeeInFrame.from_bytes(frame))
                    self.serial_in = self.serial_in[length+4:]
                else:
                    break
            except IndexError:
                break

    def handle_xbee_out(self):
        '''
        Get frames in self.frames_out and write to serial
        '''
        while True:
            try:
                frame = self.frames_out.get_nowait()
                logging.debug("[SERIAL] frame: {}".format(hexlify(bytes(frame))))
                if isinstance(frame, XBeeTXRequest):
                    self.info['tx_total'] += 1
                cnt = self.ser.write(bytes(frame))
                logging.debug("[SERIAL] {} bytes written".format(cnt))
            except Empty:
                break



if __name__ == "__main__":
    broker = Daemon()
    try:
        broker.run()
    except KeyboardInterrupt:
        broker.stop()
