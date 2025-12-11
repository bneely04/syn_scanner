import sys, dpkt, socket, datetime

if len(sys.argv) < 2:
    print("[ERROR] No PCAP filename provided")
    sys.exit(1)

filename = sys.argv[1]

syn_sent = {}
synack_recv = {}

try:
    f = open(filename, "rb")
    pcap = dpkt.pcap.Reader(f)
except Exception as e:
    print(f"[ERROR] Failed to read {filename}: {e}")
    sys.exit(1)

for time, buf in pcap:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data

        if not isinstance(ip, dpkt.ip.IP):
            continue
        if not isinstance(tcp, dpkt.tcp.TCP):
            continue

        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)
        flags = tcp.flags

        syn = flags & dpkt.tcp.TH_SYN
        ack = flags & dpkt.tcp.TH_ACK

        if syn and not ack:
            syn_sent[src] = syn_sent.get(src, 0) + 1

        if syn and ack:
            synack_recv[src] = synack_recv.get(src, 0) + 1

    except Exception:
        continue

f.close()

timestamp = datetime.datetime.now().isoformat()

print("\n====================")
print(f"[{timestamp}] Processed file: {filename}")
print("====================")

print("SYN counts:", syn_sent)
print("SYNACK counts:", synack_recv)

print("\nSuspicious Hosts:")

found_threat = False
for ip in syn_sent:
    syn = syn_sent[ip]
    synack = synack_recv.get(ip, 0)

    if synack == 0 or (synack > 0 and syn / synack > 3):
        print(f"  -> {ip}  (syn={syn}, synack={synack})")
        found_threat = True

if not found_threat:
    print("  None detected.")
