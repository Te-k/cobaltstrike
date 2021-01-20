import argparse
import csv
import requests
import urllib3
from urllib.parse import urljoin
from lib import decrypt_beacon, decode_config, JsonEncoder
import multiprocessing
from functools import partial
import datetime
import pandas as pd


def mp_worker( BITS, PORT, HTTP,output_list, host ):
    print("Checking {}".format(host))
    if not host.startswith("http"):
        if HTTP == True:
            host = "http://{0}:{1}".format(host, PORT)
        else :
            host = "https://{0}:{1}".format(host, PORT)
    if BITS == 64:
        uri = "/aad7"
    else :
        uri = "/aaa9"
    try:
        r = requests.get(urljoin(host, uri ), headers={'user-agent': ua}, verify=False, timeout=5)
        if r.status_code == 200:
            data = r.content
            if data.startswith(b"\xfc\xe8"):
                beacon = decrypt_beacon(data)
                if beacon:
                    config = decode_config(beacon)
                    if config:
                        print(f"Payload {BITS} bits found")
                        config["port"] = int(PORT)
                        config["host"] = host
                        config["result"] = "Found"
                        output_list.append(config)
                    else:
                        config = dict()
                        config["port"] = int(PORT)
                        config["host"] = host
                        config["result"] = "Config Extraction Failed"
                        output_list.append(config)
                        print("Config extraction failed")
                else:
                    config = dict()
                    print("Beacon extraction failed")
                    config["port"] = int(PORT)
                    config["host"] = host
                    config["result"] = "Beacon Extraction Failed"
                    output_list.append(config)
            elif data.startswith(b"MZ"):
                config = decode_config(data)
                if config:
                    print(f"Payload {BITS} bits found")
                    config["port"] = int(PORT)
                    config["host"] = host
                    config["result"] = "Found"
                    output_list.append(config)
                else:
                    config = dict()
                    print("Config extraction failed")
                    config["port"] = int(PORT)
                    config["host"] = host
                    config["result"] = "Config Extraction Failed"
                    output_list.append(config)
            else:
                config = dict()
                print(f"No {BITS} bits payload")
                config["port"] = int(PORT)
                config["host"] = host
                config["result"] = "Not Found"
                output_list.append(config)
        else:
            config = dict()
            print(f"No {BITS} bits payload")
            config["port"] = int(PORT)
            config["host"] = host
            config["result"] = "Not Found"
            output_list.append(config)
    except Exception as e :
        print("Request failed : "+str(e))
        config = dict()
        config["port"] = int(PORT)
        config["host"] = host
        config["result"] = "Request Failed"
        output_list.append(config)


def mp_handler(HOSTLIST,PROCESS, BITS, PORT, HTTP):
    #Preparing multiprocessing
    with multiprocessing.Pool(PROCESS) as p:
        with multiprocessing.Manager() as manager:
            #Shared list between process
            output_list = manager.list()
            func = partial(mp_worker, BITS, PORT, HTTP, output_list)
            with open(HOSTLIST) as f:
                hosts = f.read().split('\n')
            hosts.remove('')

            #Multiprocessing
            p.imap(func, hosts)
            p.close()
            p.join()

            #Transform list into Pandas DF to facilitate output (json, csv, ....)
            real_list = list(output_list)
            df = pd.DataFrame(real_list)
            try:
                df[".watermark"] = df[".watermark"].astype('Int64', errors='ignore')
            except KeyError:
                # Not watermark identified at al
                df[".watermark"] = 0
            return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Cobalt Strike beacon and configuration from a list of server')
    parser.add_argument('HOSTLIST', help='List of IP addresses or domains from a file')
    parser.add_argument('--PROCESS','-j', help='Number of process to be active simultaneously', default=10, type=int)
    parser.add_argument('--PORT','-p', help='Specify port on which scan will occur. Default: port 443', default=443, type=int)
    parser.add_argument('--BITS','-b', help='Specify which version of payload the script should request (32 or 64 bits). Default: 32', default=32, type=int, choices=[32, 64])
    parser.add_argument('--HTTP', help='If specified, made request  http and NOT https. Default : nothing', default=False, action='store_true')
    parser.add_argument('--format','-f', help='Specify format (csv or json). Default : csv', default="csv", choices=['csv', 'json'])
    args = parser.parse_args()

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    df = mp_handler(args.HOSTLIST, args.PROCESS, args.BITS, args.PORT, args.HTTP)
    header = ["host", "result", "ssl", "port", ".http-get.uri", ".http-post.uri", ".user-agent", ".watermark", "bits"]
    df["port"] = args.PORT
    df["ssl"] = not args.HTTP
    df["bits"] = args.BITS
    # Add columns if they are missing
    for h in header:
        if h not in df:
            df[h] = ""
    try:
        if args.format == "csv":
            df.to_csv(f'{datetime.date.today()}-{args.PORT}-test-output.csv', columns=header, index=False, doublequote=True, escapechar=",", quoting=csv.QUOTE_ALL)
            print(f'[+] Output success : {datetime.date.today()}-{args.PORT}-test-output.csv')
        else:
            df.to_json(f'{datetime.date.today()}-{args.PORT}-test-output.json', orient='records')
            print(f'[+] Output success : {datetime.date.today()}-{args.PORT}-test-output.json')
    except Exception as e:
        print("[-] Error during output : " + str(e))
