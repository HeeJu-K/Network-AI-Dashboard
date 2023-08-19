import os

import random
from scapy.all import rdpcap, wrpcap, Ether
from multiprocessing import Pool

# # code for multiple files
# def process_pcap(pcap_file):
#     # Read the pcap file
#     packets = rdpcap(pcap_file)

#     # Identify unique MAC addresses
#     unique_macs = set()
#     for packet in packets:
#         if packet.haslayer("Ether") and packet.haslayer("TCP"):  # Filter out non-Ether and non-TCP packets
#             unique_macs.add(packet["Ether"].src)
    
#     # Randomly select packets for each MAC address
#     selected_packets = []
#     for mac in unique_macs:
#         mac_packets = [packet for packet in packets if packet.haslayer("Ether") and packet["Ether"].src == mac and packet.haslayer("TCP")]
#         selected_packets.extend(random.sample(mac_packets, min(500, len(mac_packets))))

#     return selected_packets    

def process_pcap(pcap_file):
    # read the pcap file
    packets = rdpcap(pcap_file)

    mac_packet_count = {}
    max_records_per_mac = 5000

    selected_packets = []

    mac_AmazonEcho = "44:65:0d:56:cc:d3"
    mac_SSSmartCam = "00:16:6c:ab:6b:88"

    for packet in packets:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
            if src_mac == mac_AmazonEcho or dst_mac == mac_AmazonEcho:
                mac_packet_count[mac_AmazonEcho] = mac_packet_count.get(mac_AmazonEcho, 0) + 1
                if mac_packet_count[mac_AmazonEcho] <= max_records_per_mac:
                    selected_packets.append(packet)
            if src_mac == mac_SSSmartCam or dst_mac == mac_SSSmartCam:
                mac_packet_count[mac_SSSmartCam] = mac_packet_count.get(mac_SSSmartCam, 0) + 1
                if mac_packet_count[mac_SSSmartCam] <= max_records_per_mac:
                    selected_packets.append(packet)

    # filtered_devices = [packet for packet in packets if (Ether in packet) and (packet[Ether].src == mac_AmazonEcho or packet[Ether].dst == mac_AmazonEcho 
                                                                            #   or packet[Ether].src == mac_SSSmartCam or packet[Ether].dst == mac_SSSmartCam)]
    return selected_packets

def main():
    # --- filter devices ---
    # pcap_dir = "data/UNSW_dataset"
    # pcap_files = [os.path.join(pcap_dir, filename) for filename in os.listdir(pcap_dir) if filename.endswith(".pcap")]
    pcap_file = "data/UNSW_dataset/16-09-23.pcap" # single file
    pcap_files = [pcap_file]
    # Use multiple processes for parallel processing
    num_processes = os.cpu_count()
    with Pool(num_processes) as pool:
        filtered_devices_list = pool.map(process_pcap, pcap_files)
    # Merge selected packets from all processes
    filtered_devices = [packet for packet_list in filtered_devices_list for packet in packet_list]
    # Export filtered devices a new pcap file
    output_file = "data/facts/selected_devices.pcap"
    wrpcap(output_file, filtered_devices)

    # --- capture fields

if __name__ == "__main__":
    main()
