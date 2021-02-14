# portscanner module
import sys
from ctypes import *

class PortscannerReq(Structure):
    _fields_ = [
        ("src_ip",     c_char_p),
        ("dst_ip",     c_char_p),
        ("port_start", c_int),
        ("port_end",   c_int),
    ]

class PortscannerResult(Structure):
    _fields_ = [
        ("port",       c_uint16),
        ("status",     c_int),
    ]

portscanner = libc = CDLL("libportscanner.so")

def portscan_strstatus(status):
    if status == 0:
        return 'filtered'

    if status == 1:
        return 'open'

    if status == 2:
        return 'closed'

def scan(address, port_start, port_end):
    if not (isinstance(port_start, int) and isinstance(port_end, int)):
        raise TypeError

    if not isinstance(address, str):
        raise TypeError

    if port_start < 1 or port_start > 65535 or port_end < 1 or port_end > 65535:
        raise ValueError

    if port_end < port_start:
        raise ValueError

    port_count = port_end - port_start + 1

    portscan_req     = PortscannerReq(None, address.encode('utf-8'), port_start, port_end)
    portscan_result  = (PortscannerResult * port_count)()

    ret = portscanner.portscan_execute(byref(portscan_req), byref(portscan_result))

    if ret != 0:
        print("Error performing port scan [{}, {} on {}]", port_start, port_end, address)
        sys.exit(1)

    print("Port scan result:")

    for result in portscan_result:
        print(" {}  \t{}".format(result.port, portscan_strstatus(result.status)))

