import argparse, signal, sys
from scapy.all import sniff
import config
from detectors.arp_spoof   import ArpSpoofDetector
from detectors.ping_flood  import PingFloodDetector
from detectors.udp_flood   import UdpFloodDetector

detectors = [
    ArpSpoofDetector(),
    PingFloodDetector(),
    UdpFloodDetector(),
]

def dispatch(pkt):
    for d in detectors:
        try:
            d.handle(pkt)
        except Exception as e:
            pass
        
def main():
    ap = argparse.ArgumentParser(description="Mini-IDPS")
    ap.add_argument("-i", "--iface", default=config.INTERFACE,
                    help="Interface to sniff (default %(default)s)")
    args = ap.parse_args()

    # graceful shutdown
    def _sig(_sig, _frm):
        print("\n[+] Shutting down…")
        sys.exit(0)
    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)

    print(f"[+] Sniffing on {args.iface}")
    sniff(iface=args.iface, prn=dispatch, store=False)

if __name__ == "__main__":
    main()