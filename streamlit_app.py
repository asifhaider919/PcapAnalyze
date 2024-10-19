import streamlit as st
from scapy.all import rdpcap, TCP
import pandas as pd
import plotly.express as px

# Title of the app
st.title("TCP Throughput Analyzer")

# File uploader for PCAP files
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Read the PCAP file using Scapy
    try:
        packets = rdpcap(uploaded_file)

        # Filter TCP packets and extract timestamps and sizes
        tcp_data = []
        for packet in packets:
            if TCP in packet:
                timestamp = packet.time
                size = len(packet)
                tcp_data.append((timestamp, size))

        # Create a DataFrame from the collected TCP data
        df = pd.DataFrame(tcp_data, columns=["Timestamp", "Size"])
        df["TimeDelta"] = df["Timestamp"].diff().fillna(0)  # Time differences
        df["Throughput"] = df["Size"] / df["TimeDelta"].replace(0, 1)  # Bytes per second

        # Create a plotly figure
        fig = px.line(df, x="Timestamp", y="Throughput", 
                      labels={"Throughput": "Throughput (bytes/sec)"},
                      title="TCP Throughput Over Time")
        
        # Update layout for better visualization
        fig.update_traces(mode='lines+markers')
        fig.update_layout(xaxis_title="Time", yaxis_title="Throughput (bytes/sec)", 
                          hovermode='x unified')

        # Show the plot in Streamlit
        st.plotly_chart(fig)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
