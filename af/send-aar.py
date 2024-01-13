#!/bin/python3

import socket, struct
from time import sleep
from optparse import OptionParser

parser = OptionParser()
parser.add_option("--discard-session-termination",
                    action="store_false", dest="str", default=True)

(options, args) = parser.parse_args()

# -TODO: Implement the Capability Exchange Request

AF_IP = "192.168.93.71"
UE_IP = "192.168.101.3"
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

# CE-Request AVPs
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
s.connect((SERVER, PORT))

s.sendall(create_request(CER_AVPs, dict(), 257, 0, HopByHopId, EndByEndId))
data = recvall(s)
print('CEA-Received', repr(data))

s.sendall(create_request(AAR_AVPs, Control_Breaer_Params, 265, 16777236, HopByHopId + 1, EndByEndId + 1))
data = recvall(s)
print('Control Bearer Creation Status Received:', int.from_bytes(data[-4:], byteorder='big'))

print("Sleeping for 7.5 seconds so that the Core finishes the previous command...")
sleep(7.5)

s.sendall(create_request(AAR_AVPs, Audio_Breaer_Params, 265, 16777236, HopByHopId + 2, EndByEndId + 2))
data = recvall(s)
print('Audio Bearer Creation Status Received:', int.from_bytes(data[-4:], byteorder='big'))

print("Sleeping for 7.5 seconds so that the Core finishes the previous command...")
sleep(7.5)

s.sendall(create_request(AAR_AVPs, Video_Breaer_Params, 265, 16777236, HopByHopId + 3, EndByEndId + 3))
data = recvall(s)
print('Video Bearer Creation Status Received:', int.from_bytes(data[-4:], byteorder='big'))

if options.str:
    print("Sleeping for 15 seconds so that the Core finishes the previous command and then going to terminate the sessions...")
    sleep(15)


    s.sendall(create_request(STR_AVPs, Video_Breaer_Params, 275, 16777236, HopByHopId + 4, EndByEndId + 4))
    data = recvall(s)
    print('Video Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))

    print("Sleeping for 7.5 seconds so that the Core finishes the previous command...")
    sleep(7.5)

    s.sendall(create_request(STR_AVPs, Audio_Breaer_Params, 275, 16777236, HopByHopId + 5, EndByEndId + 5))
    data = recvall(s)
    print('Audio Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))

    print("Sleeping for 7.5 seconds so that the Core finishes the previous command...")
    sleep(7.5)

    s.sendall(create_request(STR_AVPs, Control_Breaer_Params, 275, 16777236, HopByHopId + 6, EndByEndId + 6))
    data = recvall(s)
    print('Control Session Termination Status Received:', int.from_bytes(data[-4:], byteorder='big'))


s.close()

