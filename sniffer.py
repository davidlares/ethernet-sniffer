#!/usr/bin/python3

import socket
import os, sys
import struct # separate packets fields
import binascii

CREATED = False
SNIFFER = 0

def header_analyzer(data):
    ip_bool = False
    # extracting the Ethernet header (14 bytes - MAC dest \ MAC source | protocol atteched)
    eth_header = struct.unpack("!6s6sH", data[:14]) # pattern and data
    # taking values and transforming it into ASCII
    destmac = binascii.hexlify(eth_header[0])
    srcmac = binascii.hexlify(eth_header[1])
    protocol = eth_header[2] >> 8
    # printing values
    print("[!] ETHERNET HEADER ")
    print("[*] Dest MAC: %s:%s%s:%s%s:%s " % (desmac[0:2],desmac[2:4],desmac[4:6],desmac[6:8],desmac[8:10],desmac[10:12]))
    print("[*] Source MAC: %s:%s%s:%s%s:%s " % (srcmac[0:2],srcmac[2:4],srcmac[4:6],srcmac[6:8],srcmac[8:10],srcmac[10:12]))
    print("[*] Protocol: %hu " % (protocol))

    # evaluating IPv4 with the HEX representation
    if protocol == 0x08:
        ip_bool = True
    # sending the remaining packet
    return data[14:], ip_bool

def iph_analyzer(data):
    # grabbing data (first 20 bytes on the remaining data packet)
    ip_header = struct.unpack('!6H4s4s', data[:20])
    

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
    # evaluating flag and remaining packet data
    if ip_bool == True:
        data_received, tcp_udp = iph_analyzer(data_received)
    else:
        return
