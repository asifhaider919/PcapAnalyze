import streamlit as st
from scapy.all import rdpcap

# Title of the app
st.title("PCAP File Protocol Analyzer")

# File uploader for PCAP files
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

if uploaded_file is not None:
    # Get the size of the uploaded file
    file_size = uploaded_file.size
    st.write(f"Size of the uploaded PCAP file: {file_size} bytes")
    st.write(f"Size: {file_size / 1024:.2f} KB")
    st.write(f"Size: {file_size / (1024 * 1024):.2f} MB")

    # Read the PCAP file using Scapy
    try:
        packets = rdpcap(uploaded_file)

        # Extract protocols and details from the packets
        protocols = set()
        packet_details = []

        for packet in packets:
            if hasattr(packet, 'name'):
                protocols.add(packet.name)
                packet_details.append(str(packet.summary()))  # Add a summary of the packet

        st.write("Protocols found in the PCAP file:")
        st.write(", ".join(protocols) if protocols else "No protocols found.")
        
        # Display packet details if available
        if packet_details:
            st.write("Packet Details:")
            for detail in packet_details:
                st.write(detail)
    
    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
