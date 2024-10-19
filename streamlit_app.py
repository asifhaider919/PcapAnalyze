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

        # Filter TCP packets and extract timestamps and sizes for uplink and downlink
        uplink_data = []
        downlink_data = []
        
        for packet in packets:
            if TCP in packet and IP in packet:
                timestamp = packet.time
                size = len(packet)

                # Determine if it's uplink or downlink
                if packet[IP].src == local_ip or not is_private_ip(packet[IP].dst):
                    uplink_data.append((timestamp, size))  # Outgoing
                elif packet[IP].dst == local_ip or not is_private_ip(packet[IP].src):
                    downlink_data.append((timestamp, size))  # Incoming

        # Create DataFrames from the collected TCP data
        uplink_df = pd.DataFrame(uplink_data, columns=["Timestamp", "Size"])
        downlink_df = pd.DataFrame(downlink_data, columns=["Timestamp", "Size"])

        # Calculate throughput
        for df in [uplink_df, downlink_df]:
            df["TimeDelta"] = df["Timestamp"].diff().fillna(0)  # Time differences
            df["Throughput"] = df["Size"] / df["TimeDelta"].replace(0, 1)  # Bytes per second

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

        # Display the figures with borders
        st.subheader("Uplink Throughput")
        st.plotly_chart(uplink_fig, use_container_width=True)

        st.subheader("Downlink Throughput")
        st.plotly_chart(downlink_fig, use_container_width=True)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
