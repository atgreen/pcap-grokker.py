import sys
import os
from scapy.all import rdpcap, TCP
from collections import defaultdict
import matplotlib.pyplot as plt

if len(sys.argv) < 2 or len(sys.argv) > 3:
    print(f"Usage: {sys.argv[0]} <pcap_file> [dest_port]")
    sys.exit(1)

pcap_file = sys.argv[1]
dest_port_filter = int(sys.argv[2]) if len(sys.argv) == 3 else None
base_name = os.path.splitext(os.path.basename(pcap_file))[0]

# Load packets
packets = rdpcap(pcap_file)

# Data structures
flows = defaultdict(set)          # flow_id -> set of seen sequence numbers
window_sizes = defaultdict(list)  # flow_id -> list of (timestamp, window size)
timestamps = defaultdict(list)    # flow_id -> list of timestamps

# Counters
total_tcp_packets = 0
retransmissions = 0

if dest_port_filter:
    print(f"Analyzing {pcap_file} with destination port filter: {dest_port_filter}\n")
else:
    print(f"Analyzing {pcap_file} (no destination port filter)\n")

for pkt in packets:
    if TCP in pkt:
        ip_layer = pkt['IP']
        tcp_layer = pkt['TCP']

        # Apply destination port filter if provided
        if dest_port_filter and tcp_layer.dport != dest_port_filter:
            continue

        total_tcp_packets += 1
        flow_id = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport)
        seq_num = tcp_layer.seq
        ts = pkt.time
        window_size = tcp_layer.window

        # Track retransmissions (same sequence number seen again)
        if seq_num in flows[flow_id]:
            retransmissions += 1
        else:
            flows[flow_id].add(seq_num)

        # Track window sizes and timestamps
        window_sizes[flow_id].append((ts, window_size))
        timestamps[flow_id].append(ts)

# Report global stats
print(f"Total TCP packets: {total_tcp_packets}")
print(f"Retransmissions detected: {retransmissions}")
print(f"Total unique flows: {len(flows)}\n")

if not flows:
    print("No flows matched the filter. Exiting.")
    sys.exit(0)

# Analyze and save plot for each flow
for flow, ws_list in window_sizes.items():
    window_values = [w for (_, w) in ws_list]
    times = timestamps[flow]

    # Normalize time: subtract the first timestamp so time starts at 0
    time_start = times[0]
    norm_times = [t - time_start for t in times]

    gaps = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]

    num_packets = len(ws_list)
    min_window = min(window_values)
    max_window = max(window_values)
    avg_window = sum(window_values) / num_packets
    min_gap = min(gaps) if gaps else 0
    max_gap = max(gaps) if gaps else 0
    avg_gap = sum(gaps) / len(gaps) if gaps else 0

    print(f"Flow {flow}:")
    print(f"  Number of packets: {num_packets}")
    print(f"  Window size: min={min_window}, max={max_window}, avg={avg_window:.2f}")
    print(f"  Inter-packet gap (sec): min={min_gap:.6f}, max={max_gap:.6f}, avg={avg_gap:.6f}")
    print()

    # Create plot
    plt.figure(figsize=(10, 5))
    plt.plot(norm_times, window_values, marker='o', linestyle='-', markersize=2)
    plt.title(f"Window Size Over Time\nFlow {flow}")
    plt.xlabel("Time (seconds, starting at 0)")
    plt.ylabel("TCP Window Size (bytes)")
    plt.grid(True)
    plt.tight_layout()

    # Sanitize filename
    flow_str = f"{flow[0]}_{flow[1]}_{flow[2]}_{flow[3]}"
    filename = f"{base_name}_flow_{flow_str}.png"
    filename = filename.replace(":", "_")  # Remove colons (IPv6)

    plt.savefig(filename)
    plt.close()
    print(f"  Plot saved to: {filename}\n")
