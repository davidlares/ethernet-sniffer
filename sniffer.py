#!/usr/bin/python3

import socket
import os, sys
import struct # separate packets fields
import binascii

CREATED = False
SNIFFER = 0

def header(data):
    ip_bool = False
    # extracting the Ethernet header (14 bytes - MAC dest \ MAC source | protocol atteched)
    eth_header = struct.unpack("!6s6sH", data[:14]) # pattern and data
    # taking values and transforming it into ASCII
    destmac = binascii.hexlify(eth_header[0])
    srcmac = binascii.hexlify(eth_header[1])
    protocol = eth_header[2] >> 8
    # sending the remaining packet
    data = data[14:]

if __name__ == "__main__":
    # checking status
    if CREATED == False:
        # creating a socket object (using RAW packets) - this won't be attached to any port
        snf = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        # set to True
        CREATED = True
    # receiving data (2 MB)
    data_received = snf.recv(2048)
    # sys command for clearing the screen
    os.system('clear')
    # this custom function will return the data and a boolean flag for status
    data_received, ip_bool = header_analyzer(data_received)
