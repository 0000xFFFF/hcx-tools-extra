#!/usr/bin/env python3

import re
import os


def hex2str(hex_string):
    try:
        return bytes.fromhex(hex_string).decode("utf-8")
    except ValueError:
        return "HEX ERROR"


def parse_hash_line(line):
    """Parse a hash line and return its components."""
    parts = line.split("*")
    if len(parts) < 6:
        return None
    
    hash_type = parts[1]
    hash_value = parts[2]
    bssid = parts[3]
    mac = parts[4]
    essid = hex2str(parts[5])
    type_str = "PMKID" if hash_type == "01" else "EAPOL" if hash_type == "02" else "UNKNOWN"
    
    return {
        'line': line,
        'type': type_str,
        'hash': hash_value,
        'bssid': bssid,
        'mac': mac,
        'essid': essid
    }


def rslatin_check(s):
    return bool(re.search(r'[čćšžđČĆŠŽÐ]', s))


def rslatin_replace(s):
    translations = str.maketrans("čćšžđČĆŠŽÐ", "ccszdCCSZD")
    return s.translate(translations)


def wordlst2args(wordlst):
    return " ".join(f'-s "{word}"' for word in wordlst)


def load_config_file(filepath):
    """Load lines from a config file, stripping whitespace and ignoring empty lines."""
    if not os.path.exists(filepath):
        return []
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def get_script_dir():
    """Get the directory where the script is located."""
    return os.path.dirname(os.path.abspath(__file__))
