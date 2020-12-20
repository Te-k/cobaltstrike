import argparse
import json
import os
import sys
from lib import decrypt_beacon, decode_config, JsonEncoder
"""
Extract configuration from a Cobalt Strike beacon

Author : Etienne Maynier, Amnesty Tech
Email: tek@randhome.io
Date : March 2020
"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Cobalt Strike configuration')
    parser.add_argument('PAYLOAD', help='A Cobalt Strike beacon')
    parser.add_argument('--json', '-j', action="store_true", help='Print json')
    parser.add_argument('--dump', '-D', help='Extract the beacon (only if the beacon is encrypted)')
    args = parser.parse_args()

    if not os.path.isfile(args.PAYLOAD):
        print("Not a file")
        sys.exit(-1)

    with open(args.PAYLOAD, "rb") as f:
        data = f.read()

    if data.startswith(b"\xfc\xe8") or data.startswith(b"\xfc\x48"):
        # Encrypted beacon
        payload = decrypt_beacon(data)
        if payload:
            if args.dump:
                with open(args.dump, "wb+") as f:
                    f.write(payload)
                    print("Beacon written in {}".format(args.dump))
            data = payload
        else:
            print("Looks like an encrypted beacon but impossible to find the base address")
            sys.exit(-1)

    config = decode_config(data)
    if config:
        if args.json:
            print(json.dumps(config, indent=4, sort_keys=True, cls=JsonEncoder))
        else:
            for d in config:
                if isinstance(config[d], bytearray):
                    print("{:30} {}".format(d, config[d].hex()))
                else:
                    print("{:30} {}".format(d, config[d]))
    else:
        print("Configuration not found")
