#!/usr/bin/env python3

import socket
import struct

GROUP = '224.0.23.12'
PORT = 3671

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind( (GROUP, PORT) )
mreq = struct.pack("4sl", socket.inet_aton( GROUP ), socket.INADDR_ANY)
sock.setsockopt( socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

def f_src_addr( b ):
    return "{}.{}.{}".format( (b[0]&0xF0)>>4, b[0]&0xF, b[1] )

def f_dst_addr( b ):
    return "{}/{}/{}".format( (b[0]&0xF0)>>4, b[0]&0xF, b[1] )

class CEMI:
    CMD_REQUEST = 0
    CMD_RESPONSE = 0b0001000000
    CMD_WRITE = 0b0010000000 # 0x80
    CMD_UNKNOWN = -1

    def __init__(self):
        pass

    @classmethod
    def from_dgram(cls, dgram):
        cemi = cls()

        print("DEBUG: dgram={}".format( dgram ))

        offset = 0

        # read header length
        header_length = dgram[ offset ]
        # read header
        header = dgram[ 1 : header_length ]
        (proto_version, service_identifier, total_length ) = struct.unpack( "BHB", header )
        cemi.proto_version = proto_version
        # read payload length
        total_length -= header_length
        offset += header_length
        # read payload, reset offset to 0
        payload = dgram[ offset : ]
        #payload = bytes("\x08\x01\xc0\xa8\xb2\x1c\x8f\x04", "utf8")
        p = 0
        # message code (1 byte)
        cemi.message_code = payload[ p ]
        p += 1
        # additional info
        additional_length = payload[ p ]
        p += 1
        cemi.additional_info = payload[ p : (p + additional_length - 1) ]
        p += additional_length
        
        # control fields
        ctrl1 = payload[ p ]
        p += 1

        cemi.extended_frame = ctrl1 & 0x80
        # 0x40 reserved
        cemi.do_not_repeat = ctrl1 & 0x20
        cemi.system_broadcast = ctrl1 & 0x10
        cemi.priority = (ctrl1 & 0b1100 >> 2)
        cemi.ack_requested = ctrl1 & 0x02
        cemi.error = ctrl1 & 0x01 # L_DATA.con

        ctrl2 = payload[ p ]
        p += 1

        cemi.group_address = ctrl2 & 0x80
        cemi.hop_count = (ctrl2 & 0b01110000) >> 4
        cemi.extended_frame_format = ctrl2 & 0xF
        
        # source address
        cemi.src_addr = payload[ p:p+2 ]
        cemi.src_addr_str = f_src_addr( cemi.src_addr )
        p += 2

        # destination address
        cemi.dst_addr = payload[ p:p+2 ]
        cemi.dst_addr_str = f_dst_addr( cemi.dst_addr )
        p += 2

        # data length
        data_length = payload[ p ]
        p += 1
        
        # data
        data = payload[ p: ]
        tpci_apci = (data[0] << 8 | data[1])
        apci = tpci_apci & 0x3ff

        if apci == 0:
            cemi.cmd = CEMI.CMD_REQUEST
        elif apci & CEMI.CMD_WRITE == CEMI.CMD_WRITE:
            cemi.cmd = CEMI.CMD_WRITE
        elif apci & CEMI.CMD_RESPONSE == CEMI.CMD_RESPONSE:
            cemi.cmd = CEMI.CMD_RESPONSE
        else:
            cemi.cmd = CEMI.CMD_UNKNOWN

        # data starts in first place
        apdu = data[1:]

        # tpci
        if len(apdu) == 1:
            cemi.data = [apci & 0b00111111]
        else:
            cemi.data = data[2:]

        return cemi



while True:
    dgram = sock.recv( 4096 )
    cemi = CEMI.from_dgram( dgram )
    print( "{} {} -> cmd: {:#014b} data: {}".format( cemi.src_addr_str, cemi.dst_addr_str, cemi.cmd, cemi.data ) )

    #parse_packet( dgram )
