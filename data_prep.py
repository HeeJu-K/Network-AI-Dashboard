import os
import random
from scapy.all import rdpcap, wrpcap
from multiprocessing import Pool

def process_pcap(pcap_file):
    # Read the pcap file
    packets = rdpcap(pcap_file)

    # Identify unique MAC addresses
    unique_macs = set()
    for packet in packets:
        if packet.haslayer("Ether") and packet.haslayer("TCP"):  # Filter out non-Ether and non-TCP packets
            unique_macs.add(packet["Ether"].src)
    
    # Randomly select packets for each MAC address
    selected_packets = []
    for mac in unique_macs:
        mac_packets = [packet for packet in packets if packet.haslayer("Ether") and packet["Ether"].src == mac and packet.haslayer("TCP")]
        selected_packets.extend(random.sample(mac_packets, min(500, len(mac_packets))))

    return selected_packets

def main():
    # List pcap files
    pcap_dir = "data/UNSW_dataset"
    pcap_files = [os.path.join(pcap_dir, filename) for filename in os.listdir(pcap_dir) if filename.endswith(".pcap")]

    # Use multiple processes for parallel processing
    num_processes = os.cpu_count()
    with Pool(num_processes) as pool:
        selected_packets_list = pool.map(process_pcap, pcap_files)
    
    # Merge selected packets from all processes
    all_selected_packets = [packet for packets in selected_packets_list for packet in packets]

    # Export to a new pcap file
    output_file = "data/facts/selected_packets.pcap"
    wrpcap(output_file, all_selected_packets)

if __name__ == "__main__":
    main()
