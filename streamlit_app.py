import streamlit as st
from scapy.all import rdpcap

# Title of the app
st.title("PCAP File Protocol Analyzer")

# File uploader for PCAP files
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

protocol_filter = st.selectbox("Select Protocol to Filter", ["All", "mDNS", "IGMP", "LLMNR"])

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
        filtered_details = []
        for packet in packets:
            if protocol_filter == "All" or (protocol_filter in str(packet)):
                filtered_details.append(packet.summary())

        st.write("Filtered Packet Details:")
        if filtered_details:
            for detail in filtered_details:
                st.write(detail)
        else:
            st.write("No packets found for the selected protocol.")
    
    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
