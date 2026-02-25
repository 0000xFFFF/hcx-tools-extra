#!/usr/bin/env python3

import re
import os
import subprocess
import sys


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


def load_wordlist_set(wordlist_paths, min_length=4):
    """Load words from multiple wordlist files into a set."""
    word_set = set()
    for filepath in wordlist_paths:
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'r') as f:
            for line in f:
                word = line.strip().lower()
                if len(word) >= min_length:
                    word_set.add(word)
    return word_set


def write_file_with_permissions(filepath, content, mode=0o755):
    """Write content to a file and set its permissions."""
    with open(filepath, 'w') as f:
        f.write(content)
    os.chmod(filepath, mode)


def read_lines_from_file(filepath):
    """Read and return non-empty lines from a file."""
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]


def get_unique_key(parsed):
    """Generate a unique key from BSSID and ESSID."""
    return f"{parsed['essid']}{parsed['bssid']}"


def extract_essids_from_file(filepath):
    """Extract all ESSIDs from a hash file."""
    lines = read_lines_from_file(filepath)
    essids = []
    
    for line in lines:
        parsed = parse_hash_line(line)
        if parsed:
            essids.append(parsed['essid'])
    
    return essids


def run_hcx_script(script_name, *args):
    """Run an hcx-tools script with arguments and return output."""
    cmd = [script_name] + list(args)
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except FileNotFoundError:
        print(f"Error: {script_name} not found", file=sys.stderr)
        return None
    except subprocess.SubprocessError as e:
        print(f"Error running {script_name}: {e}", file=sys.stderr)
        return None


def grep_files(search_term, file_pattern):
    """Search for a term in files matching a pattern using grep."""
    try:
        result = subprocess.run(
            ['grep', search_term] + file_pattern,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout
    except subprocess.SubprocessError as e:
        print(f"Error running grep: {e}", file=sys.stderr)
        return None