#!/usr/bin/env python3

import re

def hex2str(hex_string):
    try:
        return bytes.fromhex(hex_string).decode("utf-8")
    except ValueError:
        return "HEX ERROR"

def line2info(line):
    split = line.split("*")
    hash_id = split[2]
    hash_id, bssid, mac, essid = split[2], split[3], split[4], hex2str(split[5])
    bssid = bssid.upper()
    bssid = f"{bssid[0:2]}:{bssid[2:4]}:{bssid[4:6]}:{bssid[6:8]}:{bssid[8:10]}:{bssid[10:12]}"
    mac = mac.upper()
    mac = f"{mac[0:2]}:{mac[2:4]}:{mac[4:6]}:{mac[6:8]}:{mac[8:10]}:{mac[10:12]}"
    return [hash_id, bssid, mac, essid]

def rslatin_check(s):
    return bool(re.search(r'[čćšžđČĆŠŽÐ]', s))

def rslatin_replace(s):
    translations = str.maketrans("čćšžđČĆŠŽÐ", "ccszdCCSZD")
    return s.translate(translations)

def wordlst2args(wordlst):
    return " ".join(f'-s "{word}"' for word in wordlst)
