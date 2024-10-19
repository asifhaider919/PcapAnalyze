import streamlit as st
from scapy.all import rdpcap, TCP
import pandas as pd
import plotly.graph_objects as go

# Title of the app
st.title("TCP Throughput Analyzer")

# File uploader for PCAP files
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Read the PCAP file using Scapy
    try:
        packets = rdpcap(uploaded_file)

        # Define your local IP address (change this as needed)
        local_ip = st.text_input("Enter your local IP address:", "192.168.1.2")  # Example IP

        # Filter TCP packets and extract timestamps and sizes for uplink and downlink
        uplink_data = []
        downlink_data = []
        
        for packet in packets:
            if TCP in packet:
                timestamp = packet.time
                size = len(packet)

                # Determine if it's uplink or downlink
                if packet[IP].src == local_ip:
                    uplink_data.append((timestamp, size))  # Outgoing
                elif packet[IP].dst == local_ip:
                    downlink_data.append((timestamp, size))  # Incoming

        # Create DataFrames from the collected TCP data
        uplink_df = pd.DataFrame(uplink_data, columns=["Timestamp", "Size"])
        downlink_df = pd.DataFrame(downlink_data, columns=["Timestamp", "Size"])

        # Calculate throughput
        for df in [uplink_df, downlink_df]:
            df["TimeDelta"] = df["Timestamp"].diff().fillna(0)  # Time differences
            df["Throughput"] = df["Size"] / df["TimeDelta"].replace(0, 1)  # Bytes per second

        # Create plotly figure
        fig = go.Figure()
        
        # Uplink trace
        fig.add_trace(go.Scatter(x=uplink_df["Timestamp"], y=uplink_df["Throughput"],
                                 mode='lines+markers', name='Uplink Throughput',
                                 line=dict(color='blue')))

        # Downlink trace
        fig.add_trace(go.Scatter(x=downlink_df["Timestamp"], y=downlink_df["Throughput"],
                                 mode='lines+markers', name='Downlink Throughput',
                                 line=dict(color='orange')))

        # Update layout
        fig.update_layout(title="TCP Uplink and Downlink Throughput Over Time",
                          xaxis_title="Time",
                          yaxis_title="Throughput (bytes/sec)",
                          hovermode='x unified')

        # Show the plot in Streamlit
        st.plotly_chart(fig)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
