#!/usr/bin/env python3
# filepath: /home/user/.vip/mytools/hcx-tools-extra/tools/hcx-wifi

import sys
import os
import time
import atexit
import threading
import argparse
from threading import Thread, Lock, Event
from datetime import datetime
from operator import itemgetter

from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Deauth, Dot11AssoReq,
    Dot11AssoResp, Dot11Disas, Dot11ReassoReq, Dot11ReassoResp,
    Dot11ProbeReq, Dot11ProbeResp, Dot11Elt
)
from scapy.sendrecv import AsyncSniffer
from tabulate import tabulate
from getkey import getkey, keys


class Config:
    """Configuration constants"""
    CHANNELS = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    
    # WiFi table column indices
    WIFI_COLUMNS = ["BSSID", "ESSID", "PASSWORD", "PWR", "LAST SEEN", "#", "CH", "CRYPTO", "TIMESTAMP", "PACKETS"]
    WIFI_BSSID = 0
    WIFI_ESSID = 1
    WIFI_PASSWD = 2
    WIFI_PWR = 3
    WIFI_LASTSEEN = 4
    WIFI_NUM = 5
    WIFI_CH = 6
    WIFI_CRYPTO = 7
    WIFI_TIMESTAMP = 8
    WIFI_PACKETS = 9
    
    # Auth table column indices
    AUTH_COLUMNS = ["TYPE", "ADDR1", "ADDR2", "ESSID", "CH", "PWR", "LAST SEEN", "MAC TIMESTAMP", "PACKETS", "VENDOR1", "VENDOR2"]
    AUTH_TYPE = 0
    AUTH_ADDR1 = 1
    AUTH_ADDR2 = 2
    AUTH_ESSID = 3
    AUTH_CH = 4
    AUTH_PWR = 5
    AUTH_LASTSEEN = 6
    AUTH_TIMESTAMP = 7
    AUTH_PACKETS = 8
    AUTH_VENDOR1 = 9
    AUTH_VENDOR2 = 10
    
    # Probe table column indices
    PROBE_COLUMNS = ["TYPE", "STATION", "BSSID", "ESSID", "CH", "PWR", "LAST SEEN", "MAC TIMESTAMP", "PACKETS", "VENDOR"]
    PROBE_TYPE = 0
    PROBE_STATION = 1
    PROBE_BSSID = 2
    PROBE_ESSID = 3
    PROBE_CH = 4
    PROBE_PWR = 5
    PROBE_LASTSEEN = 6
    PROBE_TIMESTAMP = 7
    PROBE_PACKETS = 8
    PROBE_VENDOR = 9


class VendorLookup:
    """Handle MAC address to vendor name lookups"""
    
    def __init__(self, enable=True):
        self.enable = enable
        self.cache = []
        self.oui_lines = []
        
        if self.enable:
            self._load_oui_file()
    
    def _load_oui_file(self):
        """Load OUI file for vendor lookups"""
        oui_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "mac2ven.lst")
        try:
            with open(oui_path, 'r') as f:
                self.oui_lines = f.readlines()
        except FileNotFoundError:
            self.oui_lines = []
    
    def lookup(self, mac):
        """Look up vendor name from MAC address"""
        if not self.enable or not self.oui_lines:
            return ""
        
        mac_prefix = mac.replace(":", "").replace("-", "").upper()[0:6]
        
        # Check cache first
        for cached_mac, vendor in self.cache:
            if mac_prefix == cached_mac:
                return vendor
        
        # Search OUI file
        for line in self.oui_lines:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                oui_mac, oui_vendor = parts[0], parts[1]
                if mac_prefix == oui_mac:
                    self.cache.append([oui_mac, oui_vendor])
                    return oui_vendor
        
        return ""


class PasswordManager:
    """Manage password list from CSV file"""
    
    def __init__(self):
        self.passwords = []
        self.matched_count = 0
    
    def load(self, file_path):
        """Load passwords from CSV file"""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
            
            for line in lines:
                parts = line.strip().split("|||")
                if len(parts) >= 3:
                    self.passwords.append([parts[0], parts[1], parts[2]])
        except FileNotFoundError:
            print(f"Warning: Password file '{file_path}' not found")
    
    def find_password(self, bssid, essid):
        """Find password for given BSSID and ESSID"""
        match_bssid = bssid.replace(":", "").replace("-", "").lower()
        
        for pwd_bssid, pwd_essid, password in self.passwords:
            match_pwd = pwd_bssid.replace(":", "").replace("-", "").lower()
            if match_bssid == match_pwd and essid == pwd_essid:
                self.matched_count += 1
                return password
        
        return ""
    
    @property
    def count(self):
        return len(self.passwords)


class DataStore:
    """Store and manage WiFi, auth, and probe data"""
    
    def __init__(self):
        self.wifis = []
        self.auths = []
        self.probes = []
        self.lock = Lock()
    
    def add_or_update_wifi(self, wifi_data):
        """Add or update WiFi entry"""
        with self.lock:
            for i, wifi in enumerate(self.wifis):
                if wifi[Config.WIFI_BSSID] == wifi_data[Config.WIFI_BSSID]:
                    wifi_data[Config.WIFI_NUM] = wifi[Config.WIFI_NUM]
                    wifi_data[Config.WIFI_PACKETS] = wifi[Config.WIFI_PACKETS] + 1
                    wifi_data[Config.WIFI_PASSWD] = wifi[Config.WIFI_PASSWD]
                    self.wifis[i] = wifi_data
                    return
            
            wifi_data[Config.WIFI_NUM] = len(self.wifis) + 1
            wifi_data[Config.WIFI_PACKETS] = 1
            self.wifis.append(wifi_data)
    
    def add_or_update_auth(self, auth_data):
        """Add or update auth entry"""
        with self.lock:
            for i, auth in enumerate(self.auths):
                if (auth[Config.AUTH_TYPE] == auth_data[Config.AUTH_TYPE] and
                    auth[Config.AUTH_ADDR1] == auth_data[Config.AUTH_ADDR1] and
                    auth[Config.AUTH_ADDR2] == auth_data[Config.AUTH_ADDR2]):
                    auth_data[Config.AUTH_PACKETS] = auth[Config.AUTH_PACKETS] + 1
                    auth_data[Config.AUTH_VENDOR1] = auth[Config.AUTH_VENDOR1]
                    auth_data[Config.AUTH_VENDOR2] = auth[Config.AUTH_VENDOR2]
                    self.auths[i] = auth_data
                    return
            
            auth_data[Config.AUTH_PACKETS] = 1
            self.auths.append(auth_data)
    
    def add_or_update_probe(self, probe_data):
        """Add or update probe entry"""
        with self.lock:
            for i, probe in enumerate(self.probes):
                if (probe[Config.PROBE_STATION] == probe_data[Config.PROBE_STATION] and
                    probe[Config.PROBE_TYPE] == probe_data[Config.PROBE_TYPE]):
                    probe_data[Config.PROBE_BSSID] = probe[Config.PROBE_BSSID]
                    if probe_data.get('new_bssid') not in probe_data[Config.PROBE_BSSID]:
                        probe_data[Config.PROBE_BSSID].append(probe_data.get('new_bssid'))
                    probe_data[Config.PROBE_PACKETS] = probe[Config.PROBE_PACKETS] + 1
                    probe_data[Config.PROBE_VENDOR] = probe[Config.PROBE_VENDOR]
                    del probe_data['new_bssid']
                    self.probes[i] = probe_data
                    return
            
            probe_data[Config.PROBE_BSSID] = [probe_data.get('new_bssid', '')]
            probe_data[Config.PROBE_PACKETS] = 1
            if 'new_bssid' in probe_data:
                del probe_data['new_bssid']
            self.probes.append(probe_data)
    
    def clear_wifis(self):
        with self.lock:
            self.wifis = []
    
    def clear_auths(self):
        with self.lock:
            self.auths = []
    
    def clear_probes(self):
        with self.lock:
            self.probes = []
    
    def get_bssid_index(self, mac):
        """Find BSSID in WiFi table and return index"""
        if mac == "FF:FF:FF:FF:FF:FF":
            return "*"
        
        with self.lock:
            for wifi in self.wifis:
                if mac == wifi[Config.WIFI_BSSID]:
                    return str(wifi[Config.WIFI_NUM])
        return None


class PacketHandler:
    """Handle packet processing"""
    
    def __init__(self, data_store, password_manager, vendor_lookup):
        self.data_store = data_store
        self.password_manager = password_manager
        self.vendor_lookup = vendor_lookup
        self.enable_auths = True  # Changed to True by default
        self.enable_probes = True  # Changed to True by default
    
    def process_packet(self, packet):
        """Process incoming packet"""
        if packet.haslayer(Dot11Beacon):
            self._process_beacon(packet)
        
        if self.enable_auths:
            self._process_auth(packet)
        
        if self.enable_probes:
            self._process_probe(packet)
    
    def _process_beacon(self, packet):
        """Process beacon packet"""
        try:
            bssid = packet[Dot11].addr2.upper()
            essid = packet[Dot11Elt].info.decode(errors='ignore')
            dbm_signal = getattr(packet, 'dBm_AntSignal', '')
            stats = packet[Dot11Beacon].network_stats()
            
            wifi_data = [None] * len(Config.WIFI_COLUMNS)
            wifi_data[Config.WIFI_BSSID] = bssid
            wifi_data[Config.WIFI_ESSID] = essid
            wifi_data[Config.WIFI_PWR] = dbm_signal
            wifi_data[Config.WIFI_LASTSEEN] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            wifi_data[Config.WIFI_CH] = stats.get("channel")
            wifi_data[Config.WIFI_CRYPTO] = stats.get("crypto")
            wifi_data[Config.WIFI_TIMESTAMP] = packet[Dot11Beacon].timestamp
            
            # Check for password match
            passwd = self.password_manager.find_password(bssid, essid)
            wifi_data[Config.WIFI_PASSWD] = passwd
            
            self.data_store.add_or_update_wifi(wifi_data)
        except Exception as e:
            pass  # Silently ignore packet processing errors
    
    def _process_auth(self, packet):
        """Process authentication-related packets"""
        try:
            ptype = None
            
            if packet.haslayer(Dot11Auth):
                ptype = "Auth"
            elif packet.haslayer(Dot11Deauth):
                ptype = "Deauth"
            elif packet.haslayer(Dot11AssoReq):
                ptype = "AssoReq"
            elif packet.haslayer(Dot11AssoResp):
                ptype = "AssoResp"
            elif packet.haslayer(Dot11Disas):
                ptype = "Disas"
            elif packet.haslayer(Dot11ReassoReq):
                ptype = "ReassoReq"
            elif packet.haslayer(Dot11ReassoResp):
                ptype = "ReassoResp"
            
            if ptype:
                auth_data = [None] * len(Config.AUTH_COLUMNS)
                auth_data[Config.AUTH_TYPE] = ptype
                auth_data[Config.AUTH_ADDR1] = getattr(packet, 'addr1', '').upper()
                auth_data[Config.AUTH_ADDR2] = getattr(packet, 'addr2', '').upper()
                
                try:
                    auth_data[Config.AUTH_ESSID] = packet[Dot11Elt].info.decode(errors='ignore')
                except:
                    auth_data[Config.AUTH_ESSID] = ""
                
                auth_data[Config.AUTH_CH] = getattr(packet, 'channel', '')
                auth_data[Config.AUTH_PWR] = getattr(packet, 'dBm_AntSignal', '')
                auth_data[Config.AUTH_LASTSEEN] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                auth_data[Config.AUTH_TIMESTAMP] = getattr(packet, 'mac_timestamp', '')
                auth_data[Config.AUTH_VENDOR1] = self.vendor_lookup.lookup(auth_data[Config.AUTH_ADDR1])
                auth_data[Config.AUTH_VENDOR2] = self.vendor_lookup.lookup(auth_data[Config.AUTH_ADDR2])
                
                self.data_store.add_or_update_auth(auth_data)
        except Exception as e:
            pass  # Silently ignore packet processing errors
    
    def _process_probe(self, packet):
        """Process probe request/response packets"""
        try:
            ptype = None
            bssid = ""
            station = ""
            
            if packet.haslayer(Dot11ProbeReq):
                ptype = "ProbeReq"
                bssid = packet[Dot11].addr1.upper()
                station = packet[Dot11].addr2.upper()
            elif packet.haslayer(Dot11ProbeResp):
                ptype = "ProbeResp"
                station = packet[Dot11].addr1.upper()
                bssid = packet[Dot11].addr2.upper()
            
            if ptype:
                probe_data = [None] * len(Config.PROBE_COLUMNS)
                probe_data[Config.PROBE_TYPE] = ptype
                probe_data[Config.PROBE_STATION] = station
                probe_data['new_bssid'] = bssid
                
                try:
                    probe_data[Config.PROBE_ESSID] = packet[Dot11Elt].info.decode(errors='ignore')
                except:
                    probe_data[Config.PROBE_ESSID] = ""
                
                probe_data[Config.PROBE_CH] = getattr(packet, 'channel', '')
                probe_data[Config.PROBE_PWR] = getattr(packet, 'dBm_AntSignal', '')
                probe_data[Config.PROBE_LASTSEEN] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                probe_data[Config.PROBE_TIMESTAMP] = getattr(packet, 'mac_timestamp', '')
                probe_data[Config.PROBE_VENDOR] = self.vendor_lookup.lookup(station)
                
                self.data_store.add_or_update_probe(probe_data)
        except Exception as e:
            pass  # Silently ignore packet processing errors


class ChannelHopper:
    """Manage channel hopping"""
    
    def __init__(self, interface, channels=None):
        self.interface = interface
        self.channels = channels or Config.CHANNELS
        self.current_channel = self.channels[0]
        self.paused = Event()
        self.paused.set()  # Start unpaused (channel hopping enabled by default)
        self.running = False
        self.thread = None
    
    def set_channel(self, channel):
        """Set WiFi interface channel"""
        os.popen(f"sudo iw dev '{self.interface}' set channel {channel}")
        self.current_channel = channel
    
    def hop(self):
        """Hop to next channel"""
        pos = self.channels.index(self.current_channel)
        try:
            self.current_channel = self.channels[pos + 1]
        except IndexError:
            self.current_channel = self.channels[0]
        
        self.set_channel(self.current_channel)
    
    def _hop_loop(self):
        """Channel hopping loop"""
        while self.running:
            if not self.paused.is_set():
                self.paused.wait()
            self.hop()
            time.sleep(1)
    
    def start(self):
        """Start channel hopper thread"""
        self.running = True
        self.thread = Thread(target=self._hop_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop channel hopper"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def toggle_pause(self):
        """Toggle pause state"""
        if self.paused.is_set():
            self.paused.clear()
            return False
        else:
            self.paused.set()
            return True


class TerminalUI:
    """Handle terminal UI rendering"""
    
    def __init__(self, data_store):
        self.data_store = data_store
        self.lock = Lock()
        self.paused = Event()
        self.paused.set()
        self.running = False
        self.thread = None
        
        self.show_wifis = True
        self.show_auths = True  # Changed to True by default
        self.show_probes = True  # Changed to True by default
        self.match_bssid = True
        
        self.sort_by = "PWR"
        self.sort_reverse = True
        
        self.status = "STARTED: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.terminal_cols = 0
        self.terminal_lines = 0
        self.show_counter = 0
        
        atexit.register(self._cleanup)
    
    def _cleanup(self):
        """Cleanup on exit"""
        self._cursor_show()
    
    def _cursor_hide(self):
        print("\033[?25l", end='', flush=True)
    
    def _cursor_show(self):
        print("\033[?25h", end='', flush=True)
    
    def _cursor_reset(self):
        print("\033[0;0H", end='', flush=True)
    
    def _clear(self):
        os.system("clear")
    
    def _print_line(self, text):
        """Print a single line with padding"""
        try:
            cols = os.get_terminal_size().columns
            lines = os.get_terminal_size().lines
            
            # Initialize terminal size on first run
            if self.terminal_cols == 0 or self.terminal_lines == 0:
                self.terminal_cols = cols
                self.terminal_lines = lines
            
            if self.terminal_cols != cols or self.terminal_lines != lines:
                self.terminal_cols = cols
                self.terminal_lines = lines
                self._clear()
            
            if self.show_counter >= (self.terminal_lines - 1):
                return
            
            for line in text.split("\n"):
                line_len = len(line)
                if line_len > cols:
                    print(line[:cols], flush=True)
                else:
                    print(line + " " * (cols - line_len), flush=True)
                self.show_counter += 1
        except Exception as e:
            # Fallback if terminal size fails
            print(text, flush=True)
            self.show_counter += 1
    
    def render(self, channel, password_manager):
        """Render the UI"""
        with self.lock:
            self._cursor_reset()
            self.show_counter = 0
            
            arrow = "\u2193" if self.sort_reverse else "\u2191"
            
            wifi_count = len(self.data_store.wifis)
            pwd_count = password_manager.count
            pwd_matched = password_manager.matched_count
            
            self._print_line(f"CH {str(channel).rjust(2)} | {str(datetime.now()).ljust(26)} | COUNT: {wifi_count} | PASS: {pwd_count} ({pwd_matched}) | SORT BY: {arrow} {self.sort_by}")
            self._print_line(f"> {self.status}")
            self._print_line("")
            
            if self.show_wifis:
                self._render_wifi_table()
            
            if self.show_auths:
                self._render_auth_table()
            
            if self.show_probes:
                self._render_probe_table()
    
    def _render_wifi_table(self):
        """Render WiFi table"""
        with self.data_store.lock:
            wifis_copy = [wifi[:] for wifi in self.data_store.wifis]
        
        sort_index = Config.WIFI_COLUMNS.index(self.sort_by)
        wifis_sorted = sorted(wifis_copy, key=itemgetter(sort_index), reverse=self.sort_reverse)
        
        table = tabulate(wifis_sorted, headers=Config.WIFI_COLUMNS)
        self._print_line(table)
        self._print_line("\n")
    
    def _render_auth_table(self):
        """Render auth table"""
        with self.data_store.lock:
            auths_copy = [auth[:] for auth in self.data_store.auths]
        
        if self.match_bssid:
            for auth in auths_copy:
                addr1_idx = self.data_store.get_bssid_index(auth[Config.AUTH_ADDR1])
                addr2_idx = self.data_store.get_bssid_index(auth[Config.AUTH_ADDR2])
                if addr1_idx:
                    auth[Config.AUTH_ADDR1] = addr1_idx
                if addr2_idx:
                    auth[Config.AUTH_ADDR2] = addr2_idx
        
        table = tabulate(auths_copy, headers=Config.AUTH_COLUMNS)
        self._print_line(table)
        self._print_line("\n")
    
    def _render_probe_table(self):
        """Render probe table"""
        with self.data_store.lock:
            probes_copy = [probe[:] for probe in self.data_store.probes]
        
        if self.match_bssid:
            for probe in probes_copy:
                nums = []
                for bssid in probe[Config.PROBE_BSSID]:
                    idx = self.data_store.get_bssid_index(bssid)
                    if idx and idx not in nums:
                        nums.append(idx)
                    else:
                        nums.append(bssid)
                probe[Config.PROBE_BSSID] = str(nums).replace(" ", "").replace("[", "").replace("]", "").replace("'", "")
        
        table = tabulate(probes_copy, headers=Config.PROBE_COLUMNS)
        self._print_line(table)
        self._print_line("\n")
    
    def _ui_loop(self, channel_hopper, password_manager):
        """UI update loop"""
        while self.running:
            if not self.paused.is_set():
                self.paused.wait()
            self.render(channel_hopper.current_channel, password_manager)
            time.sleep(0.1)
    
    def start(self, channel_hopper, password_manager):
        """Start UI thread"""
        self._clear()
        self._cursor_hide()
        self.running = True
        self.thread = Thread(target=self._ui_loop, args=(channel_hopper, password_manager), daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop UI"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        self._cursor_show()
    
    def toggle_pause(self):
        """Toggle UI pause"""
        if self.paused.is_set():
            self.paused.clear()
            self.status = "PAUSED"
            return False
        else:
            self.paused.set()
            self.status = "RESUMED"
            return True
    
    def change_sorting(self, direction):
        """Change sort column"""
        pos = Config.WIFI_COLUMNS.index(self.sort_by)
        
        if direction > 0:
            try:
                self.sort_by = Config.WIFI_COLUMNS[pos + 1]
            except IndexError:
                self.sort_by = Config.WIFI_COLUMNS[0]
        else:
            try:
                self.sort_by = Config.WIFI_COLUMNS[pos - 1]
            except IndexError:
                self.sort_by = Config.WIFI_COLUMNS[-1]
    
    def toggle_sort_order(self):
        """Toggle sort order"""
        self.sort_reverse = not self.sort_reverse


class WiFiScanner:
    """Main WiFi scanner application"""
    
    def __init__(self, interface, password_file=None):
        self.interface = interface
        self.running = False
        self.sniffer = None
        
        # Initialize components
        self.data_store = DataStore()
        self.password_manager = PasswordManager()
        self.vendor_lookup = VendorLookup(enable=True)
        self.packet_handler = PacketHandler(self.data_store, self.password_manager, self.vendor_lookup)
        self.channel_hopper = ChannelHopper(interface)
        self.ui = TerminalUI(self.data_store)
        
        # Load passwords if provided
        if password_file:
            self.password_manager.load(password_file)
    
    def start(self):
        """Start the scanner"""
        self.running = True
        
        # Start channel hopper (enabled by default now)
        self.channel_hopper.start()
        
        # Start UI
        self.ui.start(self.channel_hopper, self.password_manager)
        
        # Start packet sniffer
        self.sniffer = AsyncSniffer(prn=self.packet_handler.process_packet, iface=self.interface)
        self.sniffer.start()
    
    def stop(self):
        """Stop the scanner"""
        self.running = False
        
        if self.sniffer:
            self.sniffer.stop()
        
        self.channel_hopper.stop()
        self.ui.stop()
    
    def handle_key(self, key):
        """Handle keyboard input"""
        if key == "q":
            return False
        elif key == keys.LEFT:
            self.ui.change_sorting(-1)
        elif key == keys.RIGHT:
            self.ui.change_sorting(1)
        elif key in [keys.UP, keys.DOWN]:
            self.ui.toggle_sort_order()
        elif key == " ":
            self.ui.toggle_pause()
        elif key == "s":
            self.ui._clear()
        elif key == "c":
            self.channel_hopper.hop()
        elif key == "C":
            is_running = self.channel_hopper.toggle_pause()
            self.ui.status = "RESUMED CHANNEL HOPPER" if is_running else "PAUSED CHANNEL HOPPER"
        elif key == "w":
            self.ui.show_wifis = not self.ui.show_wifis
            self.ui.status = f"show wifis: {'on' if self.ui.show_wifis else 'off'}"
        elif key == "W":
            self.data_store.clear_wifis()
            self.ui.status = "cleared wifi table"
        elif key == "a":
            self.ui.show_auths = not self.ui.show_auths
            self.ui.status = f"show auths: {'on' if self.ui.show_auths else 'off'}"
        elif key == "A":
            self.data_store.clear_auths()
            self.ui.status = "cleared auth table"
        elif key == "p":
            self.ui.show_probes = not self.ui.show_probes
            self.ui.status = f"show probes: {'on' if self.ui.show_probes else 'off'}"
        elif key == "P":
            self.data_store.clear_probes()
            self.ui.status = "cleared probe table"
        elif key == "k":
            self.packet_handler.enable_auths = not self.packet_handler.enable_auths
            if self.packet_handler.enable_auths:
                self.ui.show_auths = True
                self.ui.status = "auth collection: on"
            else:
                self.ui.show_auths = False
                self.ui.status = "auth collection: off"
        elif key == "l":
            self.packet_handler.enable_probes = not self.packet_handler.enable_probes
            if self.packet_handler.enable_probes:
                self.ui.show_probes = True
                self.ui.status = "probe collection: on"
            else:
                self.ui.show_probes = False
                self.ui.status = "probe collection: off"
        
        self.ui._clear()
        self.ui.render(self.channel_hopper.current_channel, self.password_manager)
        return True


def check_root():
    """Check if running as root"""
    return os.geteuid() == 0


def print_help():
    """Print help message"""
    print("ABOUT: uses scapy to show nearby networks,")
    print("       (optional) and tries to match them with the csv password list")
    print("USAGE: hcx-wifi <interface(mon)> [wifipasslst.csv]")
    print("KEY COMMANDS:")
    print("              q - quit")
    print("              s - clear/refresh terminal")
    print(" <LEFT> <RIGHT> - change sorting")
    print("    <UP> <DOWN> - change sorting order")
    print("          SPACE - pause")
    print("              c - hop channel")
    print("              C - toggle auto channel hopper")
    print("              w - show wifi table")
    print("              W - clear wifi table")
    print("              a - show auth table")
    print("              A - clear auth table")
    print("              p - show probe table")
    print("              P - clear probe table")
    print("              k - toggle auth collection")
    print("              l - toggle probe collection")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="WiFi network scanner using scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
KEY COMMANDS:
  q              quit
  s              clear/refresh terminal
  LEFT/RIGHT     change sorting column
  UP/DOWN        change sorting order
  SPACE          pause UI
  c              hop channel
  C              toggle auto channel hopper
  w              show wifi table
  W              clear wifi table
  a              show auth table
  A              clear auth table
  p              show probe table
  P              clear probe table
  k              toggle auth collection
  l              toggle probe collection
        """
    )
    
    parser.add_argument(
        'interface',
        help='WiFi interface in monitor mode (e.g., wlan0mon)'
    )
    
    parser.add_argument(
        'password_file',
        nargs='?',
        help='Optional CSV file with WiFi passwords (format: BSSID|||ESSID|||PASSWORD)'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    scanner = None
    try:
        # Check root privileges
        if not check_root():
            print("Error: This script requires root privileges")
            sys.exit(1)
        
        # Parse arguments
        args = parse_arguments()
        
        # Create and start scanner
        scanner = WiFiScanner(args.interface, args.password_file)
        scanner.start()
        
        # Give it a moment to start
        time.sleep(0.5)
        
        # Main loop - handle keyboard input
        while scanner.running:
            try:
                key = getkey()
                if not scanner.handle_key(key):
                    break
            except Exception as e:
                # If getkey fails, just continue
                time.sleep(0.1)
                continue
        
        # Cleanup
        if scanner:
            scanner.stop()
        print("Quitting...")
        
    except KeyboardInterrupt:
        if scanner:
            scanner.stop()
        print("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        if scanner:
            scanner.stop()
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()