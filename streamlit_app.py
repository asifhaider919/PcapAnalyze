import streamlit as st
from scapy.all import rdpcap, TCP, IP
import pandas as pd
import socket

def is_private_ip(ip):
    """Check if the IP is a private IP."""
    return ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168.")

# Title of the app
st.title("TCP Throughput Analyzer")

# File uploader for PCAP files
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Read the PCAP file using Scapy
    try:
        packets = rdpcap(uploaded_file)

        # Get local IP address dynamically
        local_ip = socket.gethostbyname(socket.gethostname())
        st.write(f"Detected local IP address: {local_ip}")

        # Initialize data holders
        sent_packets = {}
        received_acks = {}

        for packet in packets:
            if TCP in packet and IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                seq_num = packet[TCP].seq
                ack_num = packet[TCP].ack

                # Check for sent packets
                if src_ip == local_ip:
                    key = (src_ip, dst_ip)
                    sent_packets.setdefault(key, []).append(seq_num)

                # Check for ACK packets
                if dst_ip == local_ip and packet[TCP].flags & 0x10:  # ACK flag
                    ack_key = (dst_ip, src_ip)
                    received_acks.setdefault(ack_key, []).append(ack_num)

        # Create a summary DataFrame
        summary = []
        
        for key, seq_nums in sent_packets.items():
            src_ip, dst_ip = key
            # Count total sent packets
            packets_sent = len(seq_nums)
            # Count ACKs received for these packets
            acks_received = sum(1 for seq in seq_nums if seq + 1 in received_acks.get((dst_ip, src_ip), []))
            packet_loss = packets_sent - acks_received
            summary.append((src_ip, dst_ip, packets_sent, acks_received, packet_loss))

        # Create a summary DataFrame
        summary_df = pd.DataFrame(summary, columns=["Source IP", "Destination IP", "Packets Sent", "Packets Received", "Packet Loss"])

        # Display the summary table
        st.subheader("Packet Summary Between Source and Destination IPs")
        st.dataframe(summary_df)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
