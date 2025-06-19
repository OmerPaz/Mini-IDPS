# detectors/arp_spoof.py
from scapy.all import ARP
import time, threading, config

class ArpSpoofDetector:
    def __init__(self):
        self.table = {}
        self.lock  = threading.Lock()

    def handle(self, pkt):
        if not (pkt.haslayer(ARP) and pkt.op == 2):
            return
        ip, mac, now = pkt.psrc, pkt.hwsrc, time.time()

        with self.lock:
            old_mac, old_ts = self.table.get(ip, (None, 0))
            if old_mac and old_mac != mac and now - old_ts < config.ARP_TABLE_TTL:
                print(f"[!] ARP spoof for {ip}: {old_mac} ➜ {mac}")
            self.table[ip] = (mac, now)