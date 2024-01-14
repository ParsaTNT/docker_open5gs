#!/bin/python3

import socket, struct
from time import sleep
from optparse import OptionParser
import httpx
from threading import Timer
from copy import deepcopy
import select

parser = OptionParser()
parser.add_option("--send-session-termination",
                    action="store_true", dest="str", default=False)
parser.add_option("--send-abort-session",
                    action="store_true", dest="asr", default=False)

(options, args) = parser.parse_args()

# -TODO: Implement the Capability Exchange Request

AF_IP = "192.168.93.71"
UE_IP = "192.168.101.2"
UE_IMSI = "001010000000031"
SERVER = "172.22.0.39"
DIAMETER_PORT = 3868
HTTP2_PORT = 7777

def send_3_dwa(s):
    global c
    for _ in range(3):
        s.sendall(create_request(DWA_AVPs, {}, 280, 16777236, HopByHopId + c, EndByEndId + c, flags=0x00))
        c += 1
        sleep(1)

def recvall(sock, handle_dwr = True):
    global c
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    if handle_dwr:
        if int.from_bytes(data[1:4], byteorder="big") < len(data):
            if int.from_bytes(data[5:8], byteorder="big") == 280:
                s.sendall(create_request(DWA_AVPs, {}, 280, 16777236, HopByHopId + c, EndByEndId + c, flags=0x00))
                c += 1
                return data[int.from_bytes(data[1:4], byteorder="big"):]
            else:
                s.sendall(create_request(DWA_AVPs, {}, 280, 16777236, HopByHopId + c, EndByEndId + c, flags=0x00))
                c += 1
                return data[:int.from_bytes(data[1:4], byteorder="big")]
        else:
            if int.from_bytes(data[5:8], byteorder="big") == 280:
                s.sendall(create_request(DWA_AVPs, {}, 280, 16777236, HopByHopId + c, EndByEndId + c, flags=0x00))
                c += 1
                return recvall(sock)
            else:
                return data
    else:
        return data

watchdog_timer = None
c = 0
queue = []

def answerDeviceWatchdogRequest():
    global c
    global watchdog_timer
    global queue
    global s
    data = recvall(s, handle_dwr=False)
    diameter_command_code = int.from_bytes(data[5:8], byteorder='big')
    should_start = False
    if diameter_command_code == 280:
        s.sendall(create_request(DWA_AVPs, {}, 280, 16777236, HopByHopId + c, EndByEndId + c, flags=0x00))
        c += 1
        if watchdog_timer != None:
            watchdog_timer.cancel()
            watchdog_timer = Timer(0.1, answerDeviceWatchdogRequest)
            should_start = True
    else:
        print("Received Other Diameter Request...")
        if watchdog_timer != None:
            watchdog_timer.cancel()
            watchdog_timer = Timer(0.1, answerDeviceWatchdogRequest)
            should_start = True
        queue.append({"command_code": diameter_command_code, "data": data})
    if should_start and watchdog_timer != None:
        watchdog_timer.start()

HopByHopId = 0x38266d96
EndByEndId = 0x40cc0dec

counter = 1

def create_avp(avp_dict, inputs = {}):
    header = ""
    payload = ""
    padding = avp_dict['padding']

    global counter

    try:
        if avp_dict["type"] == "string":
            payload = avp_dict["val"].encode().hex()
        elif avp_dict["type"] == "session":
            if avp_dict['name'] not in inputs or inputs[avp_dict['name']] is None:
                payload = f'{avp_dict["val"]}{counter}'.encode().hex()
                counter += 1
            else:
                payload = f'{avp_dict["val"]}{inputs[avp_dict["name"]]}'.encode().hex()
            padding = inputs[f"{avp_dict['name']}.padding"]
        elif avp_dict["type"] == "number":
            payload = f"{avp_dict['val']:0{avp_dict['val_len'] * 2}x}"
        elif avp_dict["type"] == "input-number":
            if avp_dict['val'] not in inputs or inputs[avp_dict['val']] is None:
                print(f"Discarding Number-AVP [{avp_dict['name']}] with value [{avp_dict['val']}] because not found [{avp_dict['val'] not in inputs}] or is None [{inputs[avp_dict['val']] is None}]")
                return ""
            payload = f"{inputs[avp_dict['val']]:0{avp_dict['val_len'] * 2}x}"
        elif avp_dict["type"] == "input-string":
            if avp_dict['val'] not in inputs or inputs[avp_dict['val']] is None:
                print(f"Discarding String-AVP [{avp_dict['name']}] with value [{avp_dict['val']}] because not found [{avp_dict['val'] not in inputs}] or is None [{inputs[avp_dict['val']] is None}]")
                return ""
            payload = inputs[avp_dict['val']].encode().hex()
            padding = inputs[f"{avp_dict['val']}.padding"]
        elif avp_dict["type"] == "ip":
            payload = f"{struct.unpack('!L', socket.inet_aton(avp_dict['val']))[0]:08x}"
        elif avp_dict["type"] == "ip_family":
            payload = f"{avp_dict['family']}{struct.unpack('!L', socket.inet_aton(avp_dict['val']))[0]:08x}"
        elif avp_dict["type"] == "grouped":
            for sub_avp in avp_dict["val"]:
                payload += create_avp(sub_avp, inputs)
        else:
            raise ValueError(f"Can not find AVP type '{avp_dict['type']}'.")
    except Exception as e:
        print(f"Error in parsing AVP {avp_dict['name']} with inputs '{inputs}'...")
        raise e
    
    header += f"{avp_dict['code']:08x}"
    header += f"{avp_dict['flags']}"
    header += f"{int(len(payload) / 2) + int(len(avp_dict['header-extras']) / 2) + int(len(avp_dict['flags']) / 2) + 7:06x}"
    header += f"{avp_dict['header-extras']}"

    return f"{header}{payload}{padding}"

def create_request(AVPs, inputs, CommandCode, AppId, HBHId, EBEId, version = 1, flags = 0xc0):
    output = ""
    total_len = 20

    # Processing the AVPs
    for avp in AVPs:
        avp_bytes = create_avp(avp, inputs)
        output += avp_bytes
        total_len += int(len(avp_bytes) / 2)

    # Adding Diameter header
    output = f"{version:02x}{total_len:06x}{flags:02x}{CommandCode:06x}{AppId:08x}{HBHId:08x}{EBEId:08x}{output}"
    return bytes.fromhex(output)

# CE-Request AVPs
CER_AVPs = [
    {
        "name"          : "Origin-Host",
        "code"          : 264,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "0000",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Origin-Realm",
        "code"          : 296,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Host-IP-Address",
        "code"          : 257,
        "type"          : "ip_family",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "0000",
        "family"        : "0001",
        "val"           : AF_IP,
    },
    {
        "name"          : "Vendor-Id",
        "code"          : 266,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 0,
    },
    {
        "name"          : "Product-Name",
        "code"          : 269,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "00",
        "padding"       : "00",
        "val"           : "shkatebi97-dummy-af",
    },
    {
        "name"          : "Supported-Vendor-Id",
        "code"          : 265,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 10415,
    },
    {
        "name"          : "Auth-Application-Id",
        "code"          : 258,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 16777236,
    },
    {
        "name"          : "Vendor-Specific-Application-Id",
        "code"          : 260,
        "type"          : "grouped",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 
        [
            {
                "name"          : "Vendor-Id",
                "code"          : 266,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 10415,
            },
            {
                "name"          : "Auth-Application-Id",
                "code"          : 258,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 16777236,
            },
        ],
    },
]

# AA-Request AVPs
AAR_AVPs = [
    {
        "name"          : "Session-Id",
        "code"          : 263,
        "type"          : "session",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "00",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org;216870113;",
    },
    {
        "name"          : "Origin-Host",
        "code"          : 264,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "0000",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Origin-Realm",
        "code"          : 296,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Auth-Application-Id",
        "code"          : 258,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 16777236,
    },
    {
        "name"          : "Vendor-Specific-Application-Id",
        "code"          : 260,
        "type"          : "grouped",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 
        [
            {
                "name"          : "Vendor-Id",
                "code"          : 266,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 10415,
            },
            {
                "name"          : "Auth-Application-Id",
                "code"          : 258,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 16777236,
            },
        ],
    },
    {
        "name"          : "Destination-Realm",
        "code"          : 283,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "epc.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "AF-Application-Identifier",
        "code"          : 504,
        "type"          : "string",
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : "IMS Services",
    },
    {
        "name"          : "Authorization-Lifetime",
        "code"          : 291,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 36000,
    },
    {
        "name"          : "Subscription-Id",
        "code"          : 443,
        "type"          : "grouped",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 
        [
            {
                "name"          : "Subscription-Id-Type",
                "code"          : 450,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 2,
            },
            {
                "name"          : "Subscription-Id-Data",
                "code"          : 444,
                "type"          : "string",
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "000000",
                "val"           : f"sip:{UE_IMSI}@epc.mnc001.mcc001.3gppnetwork.org",
            },
        ],
    },
    {
        "name"          : "Reservation-Priority",
        "code"          : 458,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000032db",
        "flags"         : "80",
        "padding"       : "",
        "val"           : 0,
    },
    {
        "name"          : "Framed-IP-Address",
        "code"          : 8,
        "type"          : "ip",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : UE_IP,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 1,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 2,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 3,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 4,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 5,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 6,
    },
    {
        "name"          : "Specific-Action",
        "code"          : 513,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 12,
    },
    {
        "name"          : "Auth-Grace-Period",
        "code"          : 276,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 0,
    },
    {
        "name"          : "Session-Timeout",
        "code"          : 27,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 36000,
    },
    {
        "name"          : "Media-Component-Description",
        "code"          : 517,
        "type"          : "grouped",
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : 
        [
            {
                "name"          : "Media-Component-Number",
                "code"          : 518,
                "type"          : "input-number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : "Media-Component-Number",
            },
            {
                "name"          : "Media-Type",
                "code"          : 520,
                "type"          : "input-number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : "Media-Type",
            },
            {
                "name"          : "Max-Requested-Bandwidth-UL",
                "code"          : 516,
                "type"          : "input-number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : "Max-Requested-Bandwidth-UL",
            },
            {
                "name"          : "Max-Requested-Bandwidth-DL",
                "code"          : 515,
                "type"          : "input-number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : "Max-Requested-Bandwidth-DL",
            },
            {
                "name"          : "Codec-Data",
                "code"          : 524,
                "type"          : "input-string",
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "0000",
                "val"           : "Codec-Data[0]",
            },
            {
                "name"          : "Codec-Data",
                "code"          : 524,
                "type"          : "input-string",
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "000000",
                "val"           : "Codec-Data[1]",
            },
            {
                "name"          : "Flow-Status",
                "code"          : 511,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : 2,
            },
            {
                "name"          : "Media-Sub-Component",
                "code"          : 519,
                "type"          : "grouped",
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : 
                [
                    {
                        "name"          : "Flow-Number",
                        "code"          : 509,
                        "type"          : "input-number",
                        "val_len"       : 4,
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : "Flow-Number",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "input-string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "000000",
                        "val"           : "Flow-Description[0]",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "input-string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : "Flow-Description[1]",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "input-string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "000000",
                        "val"           : "Flow-Description[2]",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "input-string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : "Flow-Description[3]",
                    },
                    {
                        "name"          : "Flow-Usage",
                        "code"          : 512,
                        "type"          : "input-number",
                        "val_len"       : 4,
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : "Flow-Usage",
                    },
                ],
            },
        ],
    },
]

# ST-Request AVPs
STR_AVPs = [
    {
        "name"          : "Session-Id",
        "code"          : 263,
        "type"          : "session",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "00",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org;216870113;",
    },
    {
        "name"          : "Origin-Host",
        "code"          : 264,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "0000",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Origin-Realm",
        "code"          : 296,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Destination-Realm",
        "code"          : 283,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "epc.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Auth-Application-Id",
        "code"          : 258,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 16777236,
    },
    {
        "name"          : "Vendor-Specific-Application-Id",
        "code"          : 260,
        "type"          : "grouped",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 
        [
            {
                "name"          : "Vendor-Id",
                "code"          : 266,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 10415,
            },
            {
                "name"          : "Auth-Application-Id",
                "code"          : 258,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "",
                "flags"         : "40",
                "padding"       : "",
                "val"           : 16777236,
            },
        ],
    },
    {
        "name"          : "AF-Application-Identifier",
        "code"          : 504,
        "type"          : "string",
        "header-extras" : "000028af",
        "flags"         : "c0",
        "padding"       : "",
        "val"           : "IMS Services",
    },
    {
        "name"          : "Termination-Cause",
        "code"          : 295,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 1,
    },
]

# AS-Answer AVPs
ASA_AVPs = [
    {
        "name"          : "Session-Id",
        "code"          : 263,
        "type"          : "session",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "00",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org;216870113;",
    },
    {
        "name"          : "Origin-Host",
        "code"          : 264,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "0000",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Origin-Realm",
        "code"          : 296,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Result-Code",
        "code"          : 268,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 2001,
    },
]

# DW-Answer AVPs
DWA_AVPs = [
    {
        "name"          : "Origin-Host",
        "code"          : 264,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "0000",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Origin-Realm",
        "code"          : 296,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "000000",
        "val"           : "ims.mnc001.mcc001.3gppnetwork.org",
    },
    {
        "name"          : "Result-Code",
        "code"          : 268,
        "type"          : "number",
        "val_len"       : 4,
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "",
        "val"           : 2001,
    },
]

# AAR Scenarios
Control_Breaer_Params = {
    "Session-Id": 1,
    "Session-Id.padding": "0000",
    "Media-Component-Number": 1,
    "Media-Type": 4,
    "Codec-Data[0]": "uplink\noffer\n\0",
    "Codec-Data[1]": "downlink\nanswer\n\0",
    "Codec-Data[0].padding": "0000",
    "Codec-Data[1].padding": "000000",
    "Max-Requested-Bandwidth-UL": None,
    "Max-Requested-Bandwidth-DL": None,
    "Flow-Number": 1,
    "Flow-Description[0]": f"permit out ip from 0.0.0.0 5060 to {UE_IP} 5060",
    "Flow-Description[1]": f"permit in ip from {UE_IP} 5060 to 0.0.0.0 5060",
    "Flow-Description[2]": f"permit out ip from 0.0.0.0 5061 to {UE_IP} 5061",
    "Flow-Description[3]": f"permit in ip from {UE_IP} 5061 to 0.0.0.0 5061",
    "Flow-Description[0].padding": "000000",
    "Flow-Description[1].padding": "",
    "Flow-Description[2].padding": "000000",
    "Flow-Description[3].padding": "",
    "Flow-Usage": 2,
}
Audio_Breaer_Params = {
    "Session-Id": 2,
    "Session-Id.padding": "0000",
    "Media-Component-Number": 1,
    "Media-Type": 0,
    "Codec-Data[0]": "uplink\noffer\nm=audio 49120 RTP/AVP 104 110 102 108 105 100\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 AMR-WB/16000\r\na=fmtp:110 octet-align=1\r\na=rtpmap:102 AMR/8000\r\na=rtpmap:108 AMR/8\0",
    "Codec-Data[1]": "downlink\nanswer\nm=audio 15764 RTP/AVP 104 100\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:100 telephone-event/8000\r\na=fmtp:100 0-16\r\na=ptime:20\r\na=maxptime:20\r\na=sendrecv\r\n\0",
    "Codec-Data[0].padding": "0000",
    "Codec-Data[1].padding": "0000",
    "Max-Requested-Bandwidth-UL": 64000,
    "Max-Requested-Bandwidth-DL": 64000,
    "Flow-Number": 1,
    "Flow-Description[0]": f"permit out 17 from 10.90.250.100 15764 to {UE_IP} 49120",
    "Flow-Description[1]": f"permit in 17 from {UE_IP} 49120 to 10.90.250.100 15764",
    "Flow-Description[2]": f"permit out 17 from 10.90.250.100 15765 to {UE_IP} 49121",
    "Flow-Description[3]": f"permit in 17 from {UE_IP} 49121 to 10.90.250.100 15765",
    "Flow-Description[0].padding": "000000",
    "Flow-Description[1].padding": "",
    "Flow-Description[2].padding": "000000",
    "Flow-Description[3].padding": "",
    "Flow-Usage": 0,
}
Video_Breaer_Params = {
    "Session-Id": 3,
    "Session-Id.padding": "0000",
    "Media-Component-Number": 1,
    "Media-Type": 1,
    "Codec-Data[0]": "uplink\noffer\nm=audio 49120 RTP/AVP 104 110 102 108 105 100\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 AMR-WB/16000\r\na=fmtp:110 octet-align=1\r\na=rtpmap:102 AMR/8000\r\na=rtpmap:108 AMR/8\0",
    "Codec-Data[1]": "downlink\nanswer\nm=audio 15764 RTP/AVP 104 100\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:100 telephone-event/8000\r\na=fmtp:100 0-16\r\na=ptime:20\r\na=maxptime:20\r\na=sendrecv\r\n\0",
    "Codec-Data[0].padding": "0000",
    "Codec-Data[1].padding": "0000",
    "Max-Requested-Bandwidth-UL": 128000,
    "Max-Requested-Bandwidth-DL": 128000,
    "Flow-Number": 1,
    "Flow-Description[0]": f"permit out 17 from 10.90.250.100 15764 to {UE_IP} 49120",
    "Flow-Description[1]": f"permit in 17 from {UE_IP} 49120 to 10.90.250.100 15764",
    "Flow-Description[2]": f"permit out 17 from 10.90.250.100 15765 to {UE_IP} 49121",
    "Flow-Description[3]": f"permit in 17 from {UE_IP} 49121 to 10.90.250.100 15765",
    "Flow-Description[0].padding": "000000",
    "Flow-Description[1].padding": "",
    "Flow-Description[2].padding": "000000",
    "Flow-Description[3].padding": "",
    "Flow-Usage": 0,
}

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((SERVER, DIAMETER_PORT))

s.sendall(create_request(CER_AVPs, dict(), 257, 0, HopByHopId + c, EndByEndId + c, flags=0x80))
c += 1
data = recvall(s, handle_dwr=False)
print(f'CEA-Received (length: {int.from_bytes(data[1:4], byteorder="big")} == {len(data)})')
if int.from_bytes(data[1:4], byteorder="big") < len(data):
    s.sendall(create_request(DWA_AVPs, {}, 280, 16777236, HopByHopId + c, EndByEndId + c, flags=0x00))
    c += 1
    # send_3_dwa(s)

# prev_timeout = s.timeout
# s.settimeout(1)
# data = recvall(s, handle_dwr=False)
# if len(data):
#     send_3_dwa(s)
# s.settimeout(prev_timeout)

s.sendall(create_request(AAR_AVPs, Control_Breaer_Params, 265, 16777236, HopByHopId + c, EndByEndId + c))
c += 1
data = recvall(s)
print('Control Bearer Creation Status Received:', int.from_bytes(data[-4:], byteorder='big'))

s.sendall(create_request(AAR_AVPs, Audio_Breaer_Params, 265, 16777236, HopByHopId + c, EndByEndId + c))
c += 1
data = recvall(s)
print('Audio Bearer Creation Status Received:', int.from_bytes(data[-4:], byteorder='big'))

s.sendall(create_request(AAR_AVPs, Video_Breaer_Params, 265, 16777236, HopByHopId + c, EndByEndId + c))
c += 1
data = recvall(s)
print('Video Bearer Creation Status Received:', int.from_bytes(data[-4:], byteorder='big'))

watchdog_timer = Timer(0.1, answerDeviceWatchdogRequest)
watchdog_timer.start()

if options.str:
    sleep(0.2)
    watchdog_timer.cancel()
    prev_watchdog_timer = watchdog_timer
    watchdog_timer = None
    print("Waiting for a Watchdog...", flush=True, end="")
    while prev_watchdog_timer.is_alive():
        sleep(.1)
    print()

    s.sendall(create_request(STR_AVPs, Video_Breaer_Params, 275, 16777236, HopByHopId + c, EndByEndId + c))
    c += 1
    data = recvall(s)
    print('Video Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))

    s.sendall(create_request(STR_AVPs, Audio_Breaer_Params, 275, 16777236, HopByHopId + c, EndByEndId + c))
    c += 1
    data = recvall(s)
    print('Audio Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))

    s.sendall(create_request(STR_AVPs, Control_Breaer_Params, 275, 16777236, HopByHopId + c, EndByEndId + c))
    c += 1
    data = recvall(s)
    print('Control Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))
elif options.asr:
    while True:
        o = input("Insert the session number of PCF that you want to terminate or insert 'q' to stop: ")
        if o == 'q':
            break
        session_id = int(o.split()[0])
        session_type = o.split()[1]
        with httpx.Client(http1=False, http2=True) as client:
            res = client.post(
                f"http://{SERVER}:{HTTP2_PORT}/npcf-policyauthorization/v1/app-sessions/{session_id}/terminate",
                headers={"Content-Type": "application/json"},
                json={
                    "termCause": "PDU_SESSION_TERMINATION",
                    "resUri": f"http://{AF_IP}:7777/huh"
                },
            )
            print("Received code", res.status_code)

            if res.status_code != 200 and res.status_code != 204:
                raise RuntimeError("HTTP2 Request not successful")
        
        watchdog_timer.cancel()
        watchdog_timer = None

        if len(queue) == 0:
            data = recvall(s)
            diameter_command_code = int.from_bytes(data[5:8], byteorder='big')
        else:
            data = queue[-1]["data"]
            diameter_command_code = queue[-1]["command_code"]

        if diameter_command_code == 274: 
            if session_type == "Video":
                print("Sending Abort Session Answer...")
                s.sendall(create_request(ASA_AVPs, Video_Breaer_Params, 274, 16777236, HopByHopId + c, EndByEndId + c, flags=0x40))
                c += 1
                print("Sending Video Session Termination...")
                s.sendall(create_request(STR_AVPs, Video_Breaer_Params, 275, 16777236, HopByHopId + c, EndByEndId + c))
                c += 1
                data = recvall(s)
                print('Video Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))
            elif session_type == "Audio":
                print("Sending Abort Session Answer...")
                s.sendall(create_request(ASA_AVPs, Audio_Breaer_Params, 274, 16777236, HopByHopId + c, EndByEndId + c, flags=0x40))
                c += 1
                print("Sending Audio Session Termination...")
                s.sendall(create_request(STR_AVPs, Audio_Breaer_Params, 275, 16777236, HopByHopId + c, EndByEndId + c))
                c += 1
                data = recvall(s)
                print('Audio Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))
            elif session_type == "Control":
                print("Sending Abort Session Answer...")
                s.sendall(create_request(ASA_AVPs, Control_Breaer_Params, 274, 16777236, HopByHopId + c, EndByEndId + c, flags=0x40))
                c += 1
                print("Sending Control Session Termination...")
                s.sendall(create_request(STR_AVPs, Control_Breaer_Params, 275, 16777236, HopByHopId + c, EndByEndId + c))
                c += 1
                data = recvall(s)
                print('Control Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))
            else:
                s.close()
                raise ValueError(f"Unkown sesstion type [{session_type}]")
        else:
            s.close()
            raise ValueError(f"Unkown Diameter command code [{diameter_command_code}]")

        watchdog_timer = Timer(0.1, answerDeviceWatchdogRequest)

s.close()

