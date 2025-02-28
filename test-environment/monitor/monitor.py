from scapy.all import sniff, load_layer, wrpcap
from scapy.layers.tls.handshake import TLSClientHello
import json
import threading
import time

# Load the TLS layer in Scapy
load_layer("tls")

# File to save packets
PCAP_FILE = "/tmp/scapy_live_capture.pcap"

# Load the permutations JSON file
with open("permutations_5x5.json", "r") as json_file:
    permutations_data = json.load(json_file)

# Complete Cipher Suites Mapping for TLS 1.2 and TLS 1.3 based on IANA TLS parameters
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

CIPHER_SUITES = {
    # TLS 1.2 Cipher Suites
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    #TLS 1.3 Cipher Suites
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
}

# Dictionary to map TLS version numbers to human-readable names
TLS_VERSIONS = {
    0x301: "TLS 1.0",
    0x302: "TLS 1.1",
    0x303: "TLS 1.2",
    0x304: "TLS 1.3"
}

# Mapping of cipher suites to symbolic representation
CIPHER_MAPPING = {
    0x1301: 'c1', # TLS_AES_128_GCM_SHA256
    0x1302: 'c2', # TLS_AES_256_GCM_SHA384
    0x1303: 'c3', # TLS_CHACHA20_POLY1305_SHA256
    0x1304: 'c4', # TLS_AES_128_CCM_SHA256
    0x1305: 'c5'  # TLS_AES_128_CCM_8_SHA256
}

# Function to map cipher suite ID to human-readable name
def get_cipher_suite_name(cipher_id):
    return CIPHER_SUITES.get(cipher_id, f"Unknown Cipher Suite: {cipher_id}")

def packet_callback(packet):
    """
    Callback function to process packets in real-time.
    It prints all captured packets and extracts cipher suites if they are part of a TLS ClientHello message.
    """
    ip_src = packet["IP"].src  # Source IP address
    ip_dst = packet["IP"].dst  # Destination IP address

    # Save packet immediately to PCAP file
    wrpcap(PCAP_FILE, [packet], append=True)  # Append each packet as it arrives

    # Process TLS ClientHello
    if packet.haslayer(TLSClientHello):
        handshake = packet[TLSClientHello]
        print(f"TLS ClientHello detected from {ip_src} -> {ip_dst}")

        if hasattr(handshake, 'ciphers'):
            cipher_suites = handshake.ciphers
            print(f"Supported Cipher Suites: {', '.join([get_cipher_suite_name(cipher) for cipher in cipher_suites])}")
    
        extract_cipher_suites(packet)

# Global storage for captured sequences
captured_sequences = []
last_packet_time = time.time()

def check_timeout():
    """
    Checks if 30 seconds have passed since the last captured packet.
    If so, prints the full ASCII sequence from stored sequences.
    """
    global captured_sequences, last_packet_time
    while True:
        time.sleep(5)
        if time.time() - last_packet_time > 30 and captured_sequences:
            print("\nTimeout reached. Full stored sequence:")
            print(f"Mapping: {captured_sequences}")

            ascii_chars = []

            # Pairs of two from captured_sequences
            for i in range(0, len(captured_sequences) - 1, 2):
                combined_sequence = " ".join(captured_sequences[i:i+2])
                ascii_value = next((entry["ASCII"] for entry in permutations_data if entry["Permutation"] == combined_sequence), None)

                if ascii_value is not None:
                    ascii_chars.append(chr(ascii_value))

            # Flush ASCII chars if match
            if ascii_chars:
                print(f"ASCII Output: {''.join(ascii_chars)}")
            else:
                print("No valid ASCII characters found.")

            # Reset storage
            captured_sequences = []

def extract_cipher_suites(packet):
    """
    Extracts the cipher suites from a TLS ClientHello packet and stores the mapped symbols.
    Prints the latest pair every 2nd message.
    """
    global captured_sequences, last_packet_time
    last_packet_time = time.time()
    
    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        if hasattr(client_hello, 'ciphers'):
            cipher_suites = client_hello.ciphers
            mapped_symbols = [CIPHER_MAPPING[cipher] for cipher in cipher_suites if cipher in CIPHER_MAPPING]
            captured_sequences.append(" ".join(mapped_symbols))  # Convert list to string

            
            if len(captured_sequences) % 2 == 0:
                combined_sequence = " ".join(captured_sequences[-2:])
                ascii_value = next((entry["ASCII"] for entry in permutations_data if entry["Permutation"] == combined_sequence), None)
                if ascii_value is not None:
                    print(f"Mapping: {captured_sequences[-2:]}")
                    print(f"ASCII Character: {chr(ascii_value)}")
                else:
                    print(f"Mapping: {captured_sequences[-2:]}")
                    print("ASCII Character: Not found")

def start_sniffing():
    """
    Starts sniffing network traffic and processes TLS packets.
    """
    print("Starting sniffing on network interface...")
    timeout_thread = threading.Thread(target=check_timeout, daemon=True)
    timeout_thread.start()
    sniff(filter="tcp port 443", prn=packet_callback, store=False)

if __name__ == "__main__":
    start_sniffing()