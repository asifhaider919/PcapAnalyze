import streamlit as st
from scapy.all import rdpcap, IP
import pandas as pd
import socket

def get_local_ip():
    """Get the local IP address."""
    return socket.gethostbyname(socket.gethostname())

# Title of the app
st.title("Packet Summary Analyzer")

# File uploader for PCAP files
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Read the PCAP file using Scapy
    try:
        packets = rdpcap(uploaded_file)

        # Initialize a dictionary to hold packet counts
        packet_count = {}

        # Process each packet in the PCAP file
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                key = (src_ip, dst_ip)

                # Count packets between source and destination
                if key not in packet_count:
                    packet_count[key] = 0
                packet_count[key] += 1

        # Create a summary DataFrame
        summary = [(src, dst, count) for (src, dst), count in packet_count.items()]
        summary_df = pd.DataFrame(summary, columns=["Source IP", "Destination IP", "Packets Sent"])

        # Display the summary table
        st.subheader("Packet Summary Between Different IPs")
        st.dataframe(summary_df)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
