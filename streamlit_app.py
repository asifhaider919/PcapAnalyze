import streamlit as st
from scapy.all import rdpcap, TCP, IP
import pandas as pd
import plotly.graph_objects as go
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
        uplink_data = []
        downlink_data = []
        
        for packet in packets:
            if TCP in packet and IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Determine if it's uplink or downlink
                if src_ip == local_ip or not is_private_ip(dst_ip):
                    uplink_data.append((src_ip, dst_ip))  # Outgoing
                elif dst_ip == local_ip or not is_private_ip(src_ip):
                    downlink_data.append((src_ip, dst_ip))  # Incoming

        # Create DataFrames from the collected TCP data
        uplink_df = pd.DataFrame(uplink_data, columns=["Source IP", "Destination IP"])
        downlink_df = pd.DataFrame(downlink_data, columns=["Source IP", "Destination IP"])

        # Group by Source and Destination to calculate totals
        summary_uplink = uplink_df.groupby(["Source IP", "Destination IP"]).size().reset_index(name='Packets Sent')
        summary_downlink = downlink_df.groupby(["Source IP", "Destination IP"]).size().reset_index(name='Packets Received')

        # Merge the summaries to get packet loss
        summary = pd.merge(summary_uplink, summary_downlink, on=["Source IP", "Destination IP"], how='outer').fillna(0)
        summary['Packet Loss'] = summary['Packets Sent'] - summary['Packets Received']
        summary['Packet Loss'] = summary['Packet Loss'].apply(lambda x: max(0, x))  # Ensure no negative values

        # Display the summary table
        st.subheader("Packet Summary Between Source and Destination IPs")
        st.dataframe(summary)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
