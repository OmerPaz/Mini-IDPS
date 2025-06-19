# detectors/ping_flood.py
from scapy.all import ICMP, IP
import collections, time, threading, config

class PingFloodDetector:
    def __init__(self):
        self.counts = collections.defaultdict(list)
        self.lock   = threading.Lock()

    def handle(self, pkt):
        if not (pkt.haslayer(ICMP) and pkt[ICMP].type == 8):
            return
        src, now = pkt[IP].src, time.time()
        window   = now - config.FLOOD_WINDOW_SEC

        with self.lock:
            ts = self.counts[src]
            ts.append(now)
            while ts and ts[0] < window:
                ts.pop(0)
            rate = len(ts) / config.FLOOD_WINDOW_SEC
            if rate > config.PING_PPS_LIMIT:
                print(f"[!] Ping flood from {src}: {rate:.0f} pps > {config.PING_PPS_LIMIT}")
                ts.clear()