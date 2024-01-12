#!/bin/python3

import socket, struct

# TODO: Implement the Capability Exchange Request

AF_IP = "172.27.221.202"
UE_IP = "10.46.0.2"
UE_IMSI = "001010000000031"
SERVER = "172.22.0.39"
PORT = 3868

def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data


HopByHopId = 0x38266d96
EndByEndId = 0x40cc0dec

def create_avp(avp_dict):
    header = ""
    payload = ""

    if avp_dict["type"] == "string":
        payload = avp_dict["val"].encode().hex()
    elif avp_dict["type"] == "number":
        payload = f"{avp_dict['val']:0{avp_dict['val_len'] * 2}x}"
    elif avp_dict["type"] == "ip":
        payload = f"{struct.unpack('!L', socket.inet_aton(avp_dict['val']))[0]:08x}"
    elif avp_dict["type"] == "ip_family":
        payload = f"{avp_dict['family']}{struct.unpack('!L', socket.inet_aton(avp_dict['val']))[0]:08x}"
    elif avp_dict["type"] == "grouped":
        for sub_avp in avp_dict["val"]:
            payload += create_avp(sub_avp)
    else:
        raise ValueError(f"Can not find AVP type '{avp_dict['type']}'.")
    
    header += f"{avp_dict['code']:08x}"
    header += f"{avp_dict['flags']}"
    header += f"{int(len(payload) / 2) + int(len(avp_dict['header-extras']) / 2) + int(len(avp_dict['flags']) / 2) + 7:06x}"
    header += f"{avp_dict['header-extras']}"

    return f"{header}{payload}{avp_dict['padding']}"

def create_request(AVPs, CommandCode, AppId, HBHId, EBEId, version = 1, flags = 0xc0):
    output = ""
    total_len = 20

    # Processing the AVPs
    for avp in AVPs:
        avp_bytes = create_avp(avp)
        output += avp_bytes
        total_len += int(len(avp_bytes) / 2)

    # Adding Diameter header
    output = f"{version:02x}{total_len:06x}{flags:02x}{CommandCode:06x}{AppId:08x}{HBHId:08x}{EBEId:08x}{output}"
    print(output)
    return bytes.fromhex(output)

# Add CE-Request AVPs
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

# Add AA-Request AVPs
AAR_AVPs = [
    {
        "name"          : "Session-Id",
        "code"          : 263,
        "type"          : "string",
        "header-extras" : "",
        "flags"         : "40",
        "padding"       : "00",
        "val"           : "dummy-af.ims.mnc001.mcc001.3gppnetwork.org;216870113;12",
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
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : 1,
            },
            {
                "name"          : "Media-Type",
                "code"          : 520,
                "type"          : "number",
                "val_len"       : 4,
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "",
                "val"           : 4,
            },
            {
                "name"          : "Codec-Data",
                "code"          : 524,
                "type"          : "string",
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "0000",
                "val"           : "uplink\noffer\n\0",
            },
            {
                "name"          : "Codec-Data",
                "code"          : 524,
                "type"          : "string",
                "header-extras" : "000028af",
                "flags"         : "c0",
                "padding"       : "000000",
                "val"           : "downlink\nanswer\n\0",
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
                        "type"          : "number",
                        "val_len"       : 4,
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : 1,
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "000000",
                        "val"           : f"permit out ip from 0.0.0.0 5060 to {UE_IP} 5060",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : f"permit in ip from {UE_IP} 5060 to 0.0.0.0 5060",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "000000",
                        "val"           : f"permit out ip from 0.0.0.0 5061 to {UE_IP} 5061",
                    },
                    {
                        "name"          : "Flow-Description",
                        "code"          : 507,
                        "type"          : "string",
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : f"permit in ip from {UE_IP} 5061 to 0.0.0.0 5061",
                    },
                    {
                        "name"          : "Flow-Usage",
                        "code"          : 512,
                        "type"          : "number",
                        "val_len"       : 4,
                        "header-extras" : "000028af",
                        "flags"         : "c0",
                        "padding"       : "",
                        "val"           : 2,
                    },
                ],
            },
        ],
    },
]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((SERVER, PORT))

s.sendall(create_request(CER_AVPs, 257, 0, HopByHopId, EndByEndId))
data = recvall(s)
print('Received', repr(data))

s.sendall(create_request(AAR_AVPs, 265, 16777236, HopByHopId + 1, EndByEndId + 1))
data = recvall(s)
print('Received', int.from_bytes(data[-4:], byteorder='big'))
# print('Received', repr(data[-4:]))

s.close()

