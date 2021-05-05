# Cobalt Strike Resources

This repository contains:

* `analyze.py`: a script to analyze a Cobalt Strike beacon (`python analyze.py BEACON`)
* `extract.py`: extract a beacon from an encrypted beacon
* `lib.py`: library containing functions for the other scripts
* `output.csv`: CSV file containing CS servers identified online in Dec 2020
* `rules.yar`: Yara rules for CS beacons
* `scan_list.py`: script to scan a list of servers (`python scan_list.py FILE`)
* `scan.py` : script to scan a server (`python scan.py IP`)

You can see my blog post [Analyzing Cobalt Strike for Fun and Profit](https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/) for more information.

## Identifying a Cobalt Strike server

* Default HTTPs certificate is self-signed with serial number 146473198 (sha256: 87f2085c32b6a2cc709b365f55873e207a9caa10bffecf2fd16d3cf9d94d390c)
* Default JARM signature can be (see [this article](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/))
    * 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1 for Java 11 Stack
    * 2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53 for Java 13 Stack
    * 07d14d16d21d21d07c07d14d07d21d9b2f5869a6985368a9dec764186a9175 for Java 1.8 Stack
    * 05d14d16d04d04d05c05d14d05d04d4606ef7946105f20b303b9a05200e829 for Java 1.9 Stack
* Check for valid beacon url on port 80 or 443 such as:
    * `/aaa9` or `/aab8` for 32b beacons
    * `/aab9` ou `/aac8` for 64b beacons

If it is indeed a Cobalt Strike server, you can get the payload and extract its configutation with the script `scan.py`:
```
$ python scan.py https://45.77.249.XXX/
Checking https://45.77.249.XXX/
Configuration of the x86 payload:
dns                            False
ssl                            True
port                           443
.sleeptime                     60000
.http-get.server.output
.jitter                        0
.maxdns                        255
publickey                      30819f300d06092a864886f70d010101050003818d0030818902818100ecec56e6ee516018c3152b6239b1f29f1ef930e6ce0695e62e7bdaee69f5a1e432563111f97ea180b4f095be6491f566e39ee8448b071635cfb99e8839f9de4db9c5e1319164ad7b699355fdca04358eaabe1872f5e139a71dfbe2db793c2bfe198ece6bae8544503f72e4e2d4c1df76d239fa7837450eb894eabb164e00aeff020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
.http-get.uri                  45.77.249.XXX,/updates.rss
[SNIP]

x86_64: Payload not found
```

## Analyzing a Cobalt Strike beacon

When you get a Cobalt Strike beacon, it can be a PE file, or an encrypted payload. This repository provides yara rules to check files:
```
$ yara ../github/rules.yar payload
CS_encrypted_beacon_x86 payload
```

If it is indeed a beacon, you can extract the configuration with the analyze script:
```
$ python ../github/analyze.py 95.217.197.85_32b
Unknown config command 58
Unknown config command 57
dns                            False
ssl                            True
port                           443
.sleeptime                     60000
.http-get.server.output
.jitter                        0
.maxdns                        255
publickey                      30819f300d06092a864886f70d010101050003818d00308189028181008d12bd5ea1b3827d29393c82876d00351750a28d9ffd634cdeadd0a921435d915dd6422f92c1a19bbef39d3028a19138446810f9e87e492b0adc54b8482f7d3bab264c48d1dd19fbb2be18ec427d10225533422d2c69c209cc7db5f6f1bcf449c294f4cc89493da6ced72d8f444d462efc32330f71ab3fe10c151fa8752e239d020301000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
.http-get.uri                  [REDACTED],/pixel.gif
.user-agent                    Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)
.http-post.uri                 /submit.php
.http-get.client               Cookie
[SNIP]
```

## Credits and license

Credits : [Amnesty Tech](https://www.amnesty.org/en/tech/)

This code is published under the MIT license.
