import streamlit as st
import pyshark
import os

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

    # Save the uploaded file temporarily
    temp_file_path = "temp.pcap"
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    # Analyze the protocols
    try:
        cap = pyshark.FileCapture(temp_file_path)
        protocols = set()
        
        # Extract protocols from the packets
        for packet in cap:
            if hasattr(packet, 'highest_layer'):
                protocols.add(packet.highest_layer)

        st.write("Protocols found in the PCAP file:")
        st.write(", ".join(protocols))
    
    except Exception as e:
        st.error(f"An error occurred while analyzing the PCAP file: {e}")
    
    finally:
        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
