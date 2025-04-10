# hcx-scripts

[![Python 3.12.5](https://img.shields.io/badge/Python-3.12.5-yellow.svg)](http://www.python.org/download/)

Useful python scripts for cracking/processing WPA-PBKDF2-PMKID+EAPOL hashes and passwords.

## Installation

### Requirements
* python
* [hashcat](https://github.com/hashcat/hashcat)
* [hcxtools](https://github.com/ZerBea/hcxtools)
* [hcxdumptool](https://github.com/ZerBea/hcxdumptool)
* [hcx-fastgenlst](https://github.com/0000xFFFF/hcx-fastgenlst)

### Requirements - pip
* psutil
* colorama
* tabulate
* scapy
* getkey

### Run before usage
```
./install.sh
```
This will just `ln -sfr <scripts> /usr/local/bin/.`, some scripts depend on each other...

## Processing hashes
```
hcx-info hashes.txt    - display a nice table for hashes in file
                         (MACs, BSSIDs, ESSIDs, passwords, vendor info, ...)
                         fetches passwords from hashcat if any cracked hashes detected,
                         display vendor info with -v for all macs...
hcx-cracker hashes.txt - crack wifi passwords by using their essids
hcx-potfile            - display a nice table for all hashcat passwords in potfile
```

#### Examples:
> ./hcx-info hashes.txt
```
#  TYPE   HASH             MAC AP        MAC CLIENT    ESSID             PASSWORD   
-  -----  ------...------  ------------  ------------  ----------------  -----------
1  EAPOL  195bf3...fb1ec7  4c72b90f32c6  f04f7cb94dfd  MyFast-Wifi       test1234     ...
2  PMKID  d74192...6c0580  78f29ef71570  b8e4dfd8c840  Galaxy Internet   testing123   ...
...
```

##### crack wifi passwords by using their essids
```
./hcx-cracker hashes.txt -ab    # generates gen and run scripts
./gen.sh                        # generates wordlists by network ESSID for each network
./run.sh                        # runs hashcat with generated wordlists
```

## Capturing hashes with raspberry pi and hcxdumptool
```
hcx-rpidump                     - small script that starts hcxdumptool when wlan1
                                  device is connected to raspberry pi
hcx-rpidump-install             - make systemd service and start it
hcx-rpidump-filtergen "<BSSID>" - filter your own network from attack
hcx-rpidump-wmenu               - rasberry pi waveshare menu for starting hcxdumptool
```

## Generate password wordlists for cracking
Use the newer version: [hcx-fastgenlst](https://github.com/0000xFFFF/hcx-fastgenlst)

```
hcx-genlst           - name + numer, number + name, number + name + number
hcx-genlst-num8      - numbers from 00000000 to 99999999
hcx-genlst-numcommon - common numbers (dates, etc.)
hcx-genlst-upper8    - generate upper ascii with length 8
```

#### Examples:
```
hcx-genlst -lut123 -s steve
# will generate a wordlist that has passwords like: steve66, 123Steve, 69STEVE69, ...
# -l -- lower word variation
# -u -- UPPER word variation
# -t -- Title word variation
# -1 -- word + int
# -2 -- int + word
# -3 -- int + word + int
# ..... use -h to show other options...
```

## Reacon after cracking
```
hcx-wifi            - airodump-ng clone written in python that shows you passwords of
                      nearby networks you have cracked with hashcat
hcx-wifi-genpasslst - generate password csv list for hcx-wifi
```
### GeoLocate bssids in hashes
First install this tool: [abgl](https://github.com/0000xFFFF/apple-bssid-geoloc)
```
hcx-hashesabgl hashes.txt | tee out.txt       - get bssid locations in bulk from Apple's
                                                servers and output to stdout & out.txt file
```


#### Examples:
```
./hcx-wifi-genpasslst hashes.txt > passlst.csv
./hcx-wifi wlan1mon passlst.csv
```
```
CH  4 | 2024-09-07 22:46:13.812907 | COUNT: 21 | PASS: 10 (3) | SORT BY: ↓ PWR
> RESUMED CHANNEL HOPPER

BSSID              ESSID             PASSWORD      PWR  LAST SEEN              #    CH
-----------------  ----------------  ----------  -----  -------------------  ---  ----
48:8E:EF:E6:55:22  My Home Network   password1     -37  2024-09-07 22:46:13    6     1   ...
96:9A:4A:7E:7E:7E  Network Test 1    123456789     -51  2024-09-07 22:46:13   18     4   ...
90:9A:4A:97:77:66  Super Fast AP     ...           -63  2024-09-07 22:46:13   20     4   ...
...
```



## Scripts for maindb.txt
Create a *maindb.txt* file that stores the full path of your file that contains all your hashes.
```
hcx-cap   - extract info from newly captured cap/pcapng files
hcx-new   - get newly captured hashes that are not in main hashes db
hcx-fetch - grep hcx-info for main hashes db
```

## Disclaimer
The hcx-scripts are intended for educational purposes only.
The author is not responsible or liable for any misuse, illegal activity, or damage caused by the use of these scripts.
Users are solely responsible for ensuring compliance with applicable laws and regulations.
