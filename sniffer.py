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
    print("------------------ ETHERNET HEADER ------------------")
    print("[*] Dest MAC: %s:%s:%s:%s:%s:%s" % (str(destmac[0:2],'utf8'), str(destmac[2:4],'utf8'), str(destmac[4:6],'utf8'), str(destmac[6:8],'utf8'), str(destmac[8:10],'utf8'), str(destmac[10:12],'utf8')))
    print("[*] Source MAC: %s:%s:%s:%s:%s:%s" % (str(srcmac[0:2],'utf8'),str(srcmac[2:4],'utf8'),str(srcmac[4:6],'utf8'),str(srcmac[6:8],'utf8'),str(srcmac[8:10],'utf8'),str(srcmac[10:12],'utf8')))
    print("[*] Protocol: %hu" % (protocol))

    # evaluating IPv4 with the HEX representation
    if protocol == 0x08:
        ip_bool = True
    # sending the remaining packet
    return data[14:], ip_bool

def iph_analyzer(data):
    # grabbing data (first 20 bytes on the remaining data packet)
    ip_header = struct.unpack('!6H4s4s', data[:20])
    # printing fields
    print("------------------ IP HEADER ------------------")
    print("[*] Version: %hu " % (ip_header[0] >> 12)) # 12 bits only
    print("[*] IHL: %hu " % ((ip_header[0] >> 8) & 0x0f)) # Bit-wise in Python (right-shift and &)
    print("[*] TOS: %hu " % (ip_header[0] & 0x00ff)) # tos = type of service
    print("[*] Length: %hu " % (ip_header[1])) # Total length
    print("[*] ID: %hu " % (ip_header[2])) # IP ID
    print("[*] Offset: %hu " % (ip_header[3] & 0x1fff)) # offset
    print("[*] TTL: %hu " % (ip_header[4] >> 8)) # Time to live
    print("[*] Protocol: %hu " % (ip_header[4] & 0x00ff)) # protocol
    print("[*] Checksum: %hu " % (ip_header[5])) # checksum
    print("[*] Source IP: %s " % (socket.inet_ntoa(ip_header[6]))) # source address (parsed IP)
    print("[*] Destination IP: %s " % (socket.inet_ntoa(ip_header[7]))) # destination address (parsed IP)

    # checking protocol numbers (IP protocol numbers)
    protocol = (ip_header[4] & 0x00ff)
    if protocol == 6: # 0x06
        tcp_udp = "TCP"
    elif protocol == 17: # 0x11
        tcp_udp = "UDP"
    else:
        tcp_udp = "Other"

    remaining = data[20:]
    return remaining, tcp_udp

def tcp_analizer(data):
    # getting the header -> unpacking elements
    tcp_header = struct.unpack("!2H2I4H", data[:20]) # header size
    # printing fields
    print("------------------ TCP HEADER ------------------")
    print("[*] Src Port: %hu"  % (tcp_header[0]))
    print("[*] Dest Port: %hu"  % (tcp_header[1]))
    print("[*] Seq: %hu"  % (tcp_header[2]))
    print("[*] Ack: %hu"  % (tcp_header[3]))
    print("[*] Flags: %hu"  % (tcp_header[4] >> 12))
    # handling flags
    flags = (tcp_header[4] & 0x003f)
    print("[*] URG: %hu"  % (bool(flags & 0x0020)) )
    print("[*] ACK: %hu"  % (bool(flags & 0x0010)) )
    print("[*] PSH: %hu"  % (bool(flags & 0x0008)) )
    print("[*] RST: %hu"  % (bool(flags & 0x0004)) )
    print("[*] SYN: %hu"  % (bool(flags & 0x0002)) )
    print("[*] FIN: %hu"  % (bool(flags & 0x0001)) )
    print("[*] Winsize: %hu"  % (tcp_header[5]) )
    print("[*] Checksum: %hu"  % (tcp_header[6]) )
    # remaining data
    data = data[20:]

def udp_analyzer(data):
    # getting the header - unpacking elements
    udp_header = struct.unpack("!4H", data[:8]) # header size
    print("------------------ UDP HEADER ------------------")
    print("[*] Src Port % hu" % (udp_header[0]))
    print("[*] Dest Port % hu" % (udp_header[1]))
    print("[*] Length % hu" % (udp_header[2]))
    print("[*] Checksum % hu" % (udp_header[3]))
    # remaining data
    data = data[8:]

if __name__ == "__main__":
    # looping data
    while True:
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
        if ip_bool:
            data_received, tcp_udp = iph_analyzer(data_received)

        # checking TCP/UDP
        if tcp_udp == "TCP":
            data_recv = tcp_analizer(data_received)
        elif tcp_udp == "UDP":
            data_recv = udp_analyzer(data_received)
        else:
            pass
