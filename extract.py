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
    parser = argparse.ArgumentParser(description='Extract Cobalt Strike payload')
    parser.add_argument('PAYLOAD', help='An encrypted Cobalt Strike beacon')
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
            with open(args.PAYLOAD + "_payload", "wb+") as f:
                f.write(payload)
            print("Payload written in {}".format(args.PAYLOAD + "_payload"))
        else:
            print("Looks like an encrypted beacon but impossible to find the base address")
