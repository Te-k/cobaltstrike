import struct
import struct
import re
import sys
import json
"""
Functions to analyse Cobalt Strike beacons

Author: Etienne Maynier, Amnesty Tech
Email: tek@randhome.io
Date: March 2020
"""

def xor(a, b):
    return bytearray([a[0]^b[0], a[1]^b[1], a[2]^b[2], a[3]^b[3]])

def decrypt_beacon(data):
    # Find the base address
    if data.startswith(b"\xfc\xe8"):
        # 32 bits
        # The base address of the sample change depending on the code
        ba = data.find(b"\xe8\xd4\xff\xff\xff")
        if ba == -1:
            ba = data.find(b"\xe8\xd0\xff\xff\xff")
            if ba == -1:
                return None
        ba += 5
    elif data.startswith(b"\xfc\x48"):
        # 64 bits
        ba = data.find(b"\xe8\xc8\xff\xff\xff")
        if ba == -1:
            return None
        ba += 5

    key = data[ba:ba+4]
    size = struct.unpack("I", xor(key, data[ba+4:ba+8]))[0]
    # Decrypt
    res = bytearray()
    i = ba+8
    while i < (len(data) - ba - 8):
        d = data[i:i+4]
        res += xor(d, key)
        key = d
        i += 4
    return res


CONFIG_STRUCT = {
    1: "dns_ssl",
    2: "port",
    3: ".sleeptime",
    4: ".http-get.server.output",
    5: ".jitter",
    6: ".maxdns",
    7: "publickey",
    8: ".http-get.uri",
    9: ".user-agent",
    10: ".http-post.uri",
    11: ".http-get.server.output",
    12: ".http-get.client",
    13: ".http-post.client",
    14: ".spawto",
    15: ".pipename",
    16: ".killdate_year",
    17: ".killdate_month",
    18: ".killdate_day",
    19: ".dns_idle",
    20: ".dns_sleep ",
    26: ".http-get.verb",
    27: ".http-post.verb",
    28: "shouldChunkPosts",
    29: ".post-ex.spawnto_x86",
    30: ".post-ex.spawnto_x64",
    31: ".cryptoscheme",
    35: ".proxy_type",
    37: ".watermark",
    38: ".stage.cleanup",
    39: "CFGCaution",
    40: "killdate",
    41: "text_section",
    42: "obfuscate_section",
    43: "process-inject-start-rwx",
    44: "process-inject-use-rwx",
    45: "process-inject-min_alloc",
    46: "process-inject-transform-x86",
    47: "process-inject-transform-x64",
    50: "cookieBeacon",
    51: "process-inject-execute",
    52: "process-inject-allocation-method",
    53: "process-inject-stub",
    54: "host_header",
    55: "funk"
}
MAX_SIZE = 3000


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytearray):
             return obj.hex()
        return json.JSONEncoder.default(self, obj)


def search_config(data):
    r = re.search(b"ihihik.{2}ikihik", data)
    if r:
        return r.span()[0], 105
    else:
        r = re.search(b"\.\/\.\/\.\,.{2}\.\,\.\/\.\,", data)
        if r:
            return r.span()[0], 0x2e
        else:
            # Apparently some samples have a configuration that is not obfuscated
            r = re.search(b"\x00\x01\x00\x01\x00\x02.{2}\x00\x02\x00\x01\x00\x02", data)
            if r:
                return r.span()[0], 0
    return None, None


def decode_config(data):
    START, KEY = search_config(data)
    if not START:
        print("Start position of the config struct not found")
        return None

    # Configuration is xored with 105
    conf = bytearray([c ^ KEY for c in data[START:START+MAX_SIZE]])
    data = conf

    config = {}
    i = 0
    while i < len(data) - 8:
        if data[i] == 0 and data[i+1] == 0:
            break
        dec = struct.unpack(">HHH", data[i:i+6])
        if dec[0] == 1:
            v = struct.unpack(">H", data[i+6:i+8])[0]
            config["dns"] = ((v & 1) == 1)
            config["ssl"] = ((v & 8) == 8)
        else:
            if dec[0] in CONFIG_STRUCT.keys():
                key = CONFIG_STRUCT[dec[0]]
            else:
                print("Unknown config command {}".format(dec[0]))
                key = str(dec[0])
            if dec[1] == 1 and dec[2] == 2:
                # Short
                config[key] = struct.unpack(">H", data[i+6:i+8])[0]
            elif dec[1] == 2 and dec[2] == 4:
                # Int
                config[key] = struct.unpack(">I", data[i+6:i+10])[0]
            elif dec[1] == 3:
                # Byte or string
                v = data[i+6:i+6+dec[2]]
                try:
                    config[key] = v.decode('utf-8').strip('\x00')
                except UnicodeDecodeError:
                    config[key] = v
        # Add size + header
        i += dec[2] + 6
    return config
