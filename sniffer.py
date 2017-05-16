import socket
import struct
import textwrap
import time

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def format_mac(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def format_ip(addr):
    return '.'.join(map(str, addr))

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac(dest_mac), format_mac(src_mac), socket.htons(proto), data[14:]

def ipv4_packet(data):
    version = data[0] >> 4
    header_length = (data[0] & 15) * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ip(src_ip), format_ip(dest_ip), data[header_length:]

#unpack TCP packet
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H',data[:14]) #first 14 byte parse
    offset = (offset_reserved_flags >> 12) *4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)

    return src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin, data[offset:]

#unpack UDP packet
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H',data[:8]) #first 8 byte parse
    return src_port,dest_port,size,data[8:]

#Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(map(chr,string))
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string,size)])

def information(totalPackageNumber,capturedPackageNumber,startTime):
    file = open("info.txt", "+w")
    file.write("# Of Packages : " + str(totalPackageNumber)+ '\n') 
    file.write("# Of Captured Packages : " + str(capturedPackageNumber)+ '\n') 
    file.write("Uptime : " + str(time.time() - startTime)+ ' seconds \n') 
    file.close()

def writeToTXT(fileType,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data,length):
    file = open("sniffer.txt", "a")

    if fileType==0:
        file.write(TAB_1 + 'TCP Segment:' + '\n')
        file.write(TAB_2 + 'Source Port: ' + str(src_port) +', Destination Port: ' + str(dest_port) + '\n')
        file.write(TAB_2 + 'Sequence: ' + str(sequence) +' , Acknowledgement: ' + str(acknowledgement) + '\n')
        file.write(TAB_2 + 'Flags: ' +'\n')
        file.write(TAB_3 + 'URG:' + str(flag_urg) +' , ACK: ' + str(flag_ack) +' , PSH:' + str(flag_psh) +' , RST: ' + str(flag_rst) +' , SYN:' + str(flag_syn) +' , FIN: ' + str(flag_fin) +'\n')
        file.write(TAB_2 + 'Data:' + format_multi_line(DATA_TAB_3, data) + '\n')
    else:
        file.write(TAB_1 + 'TCP Segment:')
        file.write(TAB_2 + 'Source Port: ' + str(src_port) +', Destination Port: ' + str(dest_port) +', Length : ' + str(length) + '\n')
        file.write(TAB_2 + 'Data:' + format_multi_line(DATA_TAB_3, data) + '\n')
    file.close()

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
startTime = time.time()
totalPackageNumber = 0
capturedPackageNumber = 0
while True:
    raw_data, addr = conn.recvfrom(65536)
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    
    print('\n Ethernet Frame:')
    print(TAB_1 + 'Destination: {}, Source {}, Protocol: {}'.format(dest_mac,src_mac,eth_proto))

    # 8 for IPv4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length,ttl))
        print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
        #TCP
        if proto == 6:
            capturedPackageNumber += 1
            src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data = tcp_segment(data)
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port,dest_port))
            print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence,acknowledgement))
            print(TAB_2 + 'Flags: {}')
            print(TAB_3 + 'URG:{}, ACK: {}, PSH:{}, RST: {}, SYN:{}, FIN: {}'.format(flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin))
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))
            writeToTXT(0,src_port,dest_port,sequence,acknowledgement,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data,None)
        
        #UDP
        elif proto == 17:
            capturedPackageNumber += 1
            src_port, dest_port, length, data = udp_segment(data)
            print(TAB_1 + 'UDP Segment:{}')
            print(TAB_2 + 'Soruce Port: {}, Destination Port: {}, Length: {}'.format(src_port,dest_port,length))
            print(format_multi_line(DATA_TAB_3, data))
            writeToTXT(1,src_port,dest_port,None,None,None,None,None,None,None,None,data,length)
        
        #else:
            #capturedPackageNumber += 1
            #print(TAB_1 + 'Data:')
            #print(format_multi_line(DATA_TAB_2,data))
    #else:
    #    print('Data:')
    #    print(format_multi_line(DATA_TAB_1,data))
    totalPackageNumber += 1
    information(totalPackageNumber,capturedPackageNumber,startTime)