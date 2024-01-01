import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            print('\nEthernet Frame:')
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

#Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto =struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[:14]

#Return properly  formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#Unpack IPv4 packet
def ipv4_packet(data):
     version_header_lenght = data[0]
     version = version_header_lenght >> 4
     header_lenght = (version_header_lenght & 15) * 4
     ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
     return version, header_lenght, ttl, proto, ipv4(src), ipv4(target), data[header_lenght:]

#Return properly formatted IPv4 address
def ipv4(addr):
     return '.'.join(map(str, addr))

#Unpack ICMP packet
def icmp_packet(data):
     icmp_type, code,checksum = struct.unpack('! B B H', data[:4])
     return icmp_type, code,checksum, data[data:4]

#Unpack TCP segment
def tcp_segment(data):
     (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L ')
     offset = (offset_reserved_flags >> 12) * 4
     flag_urg = (offset_reserved_flags & 32) >> 5
     flag_ack = (offset_reserved_flags & 16) >> 4
     flag_psh = (offset_reserved_flags & 8) >> 3
     flag_rst = (offset_reserved_flags & 4) >> 2
     flag_syn = (offset_reserved_flags & 2) >> 1
     flag_fin = offset_reserved_flags & 1
     return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
     
main()
         
    