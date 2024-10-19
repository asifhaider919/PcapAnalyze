import streamlit as st
from scapy.all import rdpcap, TCP
import pandas as pd
import matplotlib.pyplot as plt

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

        # Plotting
        plt.figure(figsize=(12, 6))
        plt.plot(df["Timestamp"], df["Throughput"], label='TCP Throughput', color='blue')
        plt.xlabel("Time")
        plt.ylabel("Throughput (bytes/sec)")
        plt.title("TCP Throughput Over Time")
        plt.xticks(rotation=45)
        plt.grid()
        plt.legend()

        # Show the plot in Streamlit
        st.pyplot(plt)

    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
