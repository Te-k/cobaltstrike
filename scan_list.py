import argparse
import csv
import requests
import urllib3
from urllib.parse import urljoin
from lib import decrypt_beacon, decode_config, JsonEncoder


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Cobalt Strike beacon and configuration from a list of server')
    parser.add_argument('HOSTLIST', help='List of IP addresses or domains from a fril')
    args = parser.parse_args()

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    with open(args.HOSTLIST) as f:
        hosts = f.read().split('\n')


    fout = open("output.csv", "w")
    csvout = csv.writer(fout, delimiter=',', quotechar='"')
    csvout.writerow(["Host", "Status", "SSL", "Port", "GET uri", "POST uri", "User Agent", "Watermark"])

    for host in hosts:
        print("Checking {}".format(host))
        if host.stirp() == "":
            continue
        if not host.startswith("http"):
            host = "https://{}".format(host)
        try:
            r = requests.get(urljoin(host, "/aaa9"), headers={'user-agent': ua}, verify=False, timeout=5)
            if r.status_code == 200:
                data = r.content
                if data.startswith(b"\xfc\xe8"):
                    beacon = decrypt_beacon(data)
                    if beacon:
                        config = decode_config(beacon)
                        if config:
                            csvout.writerow([
                                host,
                                "Found",
                                config["ssl"],
                                config["port"],
                                config[".http-get.uri"],
                                config[".http-post.uri"],
                                config[".user-agent"],
                                config[".watermark"]
                            ])
                            print("Payload found")
                        else:
                            csvout.writerow([host, "Config Extraction Failed", "", "", "", "", "", ""])
                            print("Config extraction failed")
                    else:
                        csvout.writerow([host, "Beacon Extraction Failed", "", "", "", "", "", ""])
                        print("Beacon extraction failed")
                elif data.startswith(b"MZ"):
                    config = decode_config(beacon)
                    if config:
                        csvout.writerow([
                            host,
                            "Found",
                            config["ssl"],
                            config["port"],
                            config[".http-get.uri"],
                            config[".http-post.uri"],
                            config[".user-agent"],
                            config[".watermark"]
                        ])
                        print("Payload found")
                    else:
                        csvout.writerow([host, "Config Extraction Failed", "", "", "", "", "", ""])
                        print("Config extraction failed")
                else:
                    csvout.writerow([host, "Not Found", "", "", "", "", "", ""])
                    print("No x86 payload")
            else:
                csvout.writerow([host, "Not Found", "", "", "", "", "", ""])
                print("No x86 payload")
        except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout, requests.exceptions.TooManyRedirects, requests.exceptions.ContentDecodingError):
            csvout.writerow([host, "Failed", "", "", "", "", "", ""])
            print("Request failed")
