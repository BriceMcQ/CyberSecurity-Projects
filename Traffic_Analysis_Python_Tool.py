from scapy.all import sniff, IP
from datetime import datetime
import pandas as pd

# Collected results will go here
log_entries = []

# Known IP protocols partial list; more can be added as needed
ip_protocols = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    89: "OSPF",
}

def resolve_protocol(proto_id):
    """Return protocol name or raw ID if unknown"""
    return ip_protocols.get(proto_id, f"Unk({proto_id})")

def record_packet(pkt):
    """Parses a single packet and extracts useful info"""
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_id = ip_layer.proto
        packet_size = len(pkt)

        proto_name = resolve_protocol(proto_id)

        # Get ports if the layer has them
        src_port = getattr(pkt.payload, 'sport', None)
        dst_port = getattr(pkt.payload, 'dport', None)

        entry = {
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "From": src_ip,
            "To": dst_ip,
            "Protocol": proto_name,
            "Src Port": src_port,
            "Dst Port": dst_port,
            "Size (bytes)": packet_size
        }

        log_entries.append(entry)

        # Print a live view to the console
        sport_str = f":{src_port}" if src_port else ""
        dport_str = f":{dst_port}" if dst_port else ""
        print(f"{src_ip}{sport_str} -> {dst_ip}{dport_str} [{proto_name}] {packet_size}B")

def run_capture(adapter_name="Ethernet"):
    """Starts sniffing traffic on the given interface and ensures results are saved on exit."""
    print(f"\n[+] Monitoring started on: {adapter_name}")
    try:
        sniff(iface=adapter_name, prn=record_packet, store=False)
    except KeyboardInterrupt:
        print("\n[!] Sniffing manually stopped by user.")
    finally:
        save_results()

def save_results():
    """Save captured data to Excel with a timestamp"""
    df = pd.DataFrame(log_entries)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"networktraffic_log_{timestamp}.xlsx"
    df.to_excel(output_file, index=False)
    print(f"[+] Log saved to: {output_file}")

if __name__ == "__main__":
    run_capture()

