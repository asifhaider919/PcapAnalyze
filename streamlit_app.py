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
                timestamp = packet.time
                size = len(packet)
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Determine if it's uplink or downlink
                if src_ip == local_ip or not is_private_ip(dst_ip):
                    uplink_data.append((src_ip, dst_ip, timestamp, size))  # Outgoing
                elif dst_ip == local_ip or not is_private_ip(src_ip):
                    downlink_data.append((src_ip, dst_ip, timestamp, size))  # Incoming

        # Create DataFrames from the collected TCP data
        uplink_df = pd.DataFrame(uplink_data, columns=["Source IP", "Destination IP", "Timestamp", "Size"])
        downlink_df = pd.DataFrame(downlink_data, columns=["Source IP", "Destination IP", "Timestamp", "Size"])

        # Calculate throughput
        for df in [uplink_df, downlink_df]:
            df["TimeDelta"] = df["Timestamp"].diff().fillna(0)  # Time differences
            df["Throughput"] = df["Size"] / df["TimeDelta"].replace(0, 1)  # Bytes per second

        # Calculate totals and losses
        total_uplink_bytes = uplink_df["Size"].sum()
        total_downlink_bytes = downlink_df["Size"].sum()
        packets_sent = len(uplink_df)
        packets_received = len(downlink_df)
        
        # Packet loss as a percentage of total packets sent vs received
        packet_loss = (packets_sent - packets_received) / packets_sent * 100 if packets_sent > 0 else 0

        # Create plotly figures with borders
        uplink_fig = go.Figure()
        uplink_fig.add_trace(go.Scatter(x=uplink_df["Timestamp"], y=uplink_df["Throughput"],
                                         mode='lines+markers', name='Uplink Throughput',
                                         line=dict(color='blue')))
        uplink_fig.update_layout(title="Uplink Throughput Over Time",
                                  xaxis_title="Time",
                                  yaxis_title="Throughput (bytes/sec)",
                                  plot_bgcolor='rgba(0,0,0,0)',
                                  paper_bgcolor='rgba(0,0,0,0)',
                                  margin=dict(l=40, r=40, t=40, b=40),
                                  width=700, height=400)
        uplink_fig.update_xaxes(showgrid=True, gridcolor='lightgray')
        uplink_fig.update_yaxes(showgrid=True, gridcolor='lightgray')

        downlink_fig = go.Figure()
        downlink_fig.add_trace(go.Scatter(x=downlink_df["Timestamp"], y=downlink_df["Throughput"],
                                           mode='lines+markers', name='Downlink Throughput',
                                           line=dict(color='orange')))
        downlink_fig.update_layout(title="Downlink Throughput Over Time",
                                    xaxis_title="Time",
                                    yaxis_title="Throughput (bytes/sec)",
                                    plot_bgcolor='rgba(0,0,0,0)',
                                    paper_bgcolor='rgba(0,0,0,0)',
                                    margin=dict(l=40, r=40, t=40, b=40),
                                    width=700, height=400)
        downlink_fig.update_xaxes(showgrid=True, gridcolor='lightgray')
        downlink_fig.update_yaxes(showgrid=True, gridcolor='lightgray')

        # Display the figures
        st.subheader("Uplink Throughput")
        st.plotly_chart(uplink_fig, use_container_width=True)

        st.subheader("Downlink Throughput")
        st.plotly_chart(downlink_fig, use_container_width=True)

        # Create a detailed summary table
        summary_data = {
            "Metric": [
                "Total Bytes Sent", 
                "Total Bytes Received", 
                "Packets Sent", 
                "Packets Received", 
                "Packet Loss (%)"
            ],
            "Value": [
                total_uplink_bytes,
                total_downlink_bytes,
                packets_sent,
                packets_received,
                packet_loss
            ]
        }
        summary_df = pd.DataFrame(summary_data)

        # Display summary table
        st.subheader("Detailed Summary Statistics")
        st.table(summary_df)

        # Add Sequence column to DataFrames
        uplink_df["Sequence"] = range(1, packets_sent + 1)
        downlink_df["Sequence"] = range(1, packets_received + 1)
        
        # Create detailed packet information
        uplink_df["Total Bytes"] = uplink_df["Size"]
        downlink_df["Total Bytes"] = downlink_df["Size"]
        
        # Create a final display DataFrame
        uplink_df["Packets Sent"] = packets_sent
        uplink_df["Packets Received"] = packets_received
        uplink_df["Packet Loss (%)"] = packet_loss

        downlink_df["Packets Sent"] = packets_sent
        downlink_df["Packets Received"] = packets_received
        downlink_df["Packet Loss (%)"] = packet_loss

        st.subheader("Uplink Packet Details")
        uplink_details = uplink_df[["Sequence", "Source IP", "Destination IP", "Total Bytes", "Packets Sent", "Packets Received", "Packet Loss (%)"]]
        st.dataframe(uplink_details)

        st.subheader("Downlink Packet Details")
        downlink_details = downlink_df[["Sequence", "Source IP", "Destination IP", "Total Bytes", "Packets Sent", "Packets Received", "Packet Loss (%)"]]
        st.dataframe(downlink_details)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
