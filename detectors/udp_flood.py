# detectors/udp_flood.py
from scapy.all import UDP, IP
import collections, time, threading, config

class UdpFloodDetector:
    def __init__(self):
        self.counts = collections.defaultdict(list)
        self.lock   = threading.Lock()

    def handle(self, pkt):
        if not pkt.haslayer(UDP):
            return
        src, now = pkt[IP].src, time.time()
        window   = now - config.FLOOD_WINDOW_SEC

        with self.lock:
            ts = self.counts[src]
            ts.append(now)
            while ts and ts[0] < window:
                ts.pop(0)
            rate = len(ts) / config.FLOOD_WINDOW_SEC
            if rate > config.UDP_PPS_LIMIT:
                print(f"[!] UDP flood from {src}: {rate:.0f} pps > {config.UDP_PPS_LIMIT}")
                ts.clear()