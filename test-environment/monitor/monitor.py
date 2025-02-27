import scapy
from scapy.all import sniff, wrpcap, conf, get_if_list, load_layer
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

# Load the TLS layer in Scapy
load_layer("tls")

# File to save packets
PCAP_FILE = "/tmp/scapy_live_capture.pcap"

# Complete Cipher Suites Mapping for TLS 1.2 and TLS 1.3 based on IANA TLS parameters
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

CIPHER_SUITES = {
    # TLS 1.2 Cipher Suites
    0x0000: "TLS_NULL_WITH_NULL_NULL",  # 0
    0x0001: "TLS_RSA_WITH_NULL_MD5",  # 1
    0x0002: "TLS_RSA_WITH_NULL_SHA",  # 2
    0x003B: "TLS_RSA_WITH_NULL_SHA256",  # 59
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",  # 4
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",  # 5
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",  # 10
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",  # 47
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",  # 53
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",  # 60
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",  # 61
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",  # 49391
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",  # 49392
    0x1301: "TLS_AES_128_GCM_SHA256",  # 49313
    0x1302: "TLS_AES_256_GCM_SHA384",  # 49314
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",  # 49315
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x00ff: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
}

# Dictionary to map TLS version numbers to human-readable names
TLS_VERSIONS = {
    0x301: "TLS 1.0",   # 769
    0x302: "TLS 1.1",   # 770
    0x303: "TLS 1.2",   # 771
    0x304: "TLS 1.3"    # 772
}

# Function to map cipher suite ID to human-readable name
def get_cipher_suite_name(cipher_id):
    return CIPHER_SUITES.get(cipher_id, f"Unknown Cipher Suite: {cipher_id}")

# Function to map TLS version to human-readable name
def get_tls_version(version):
    return TLS_VERSIONS.get(version, f"Unknown TLS Version: {version}")

def packet_callback(packet):
    """
    Callback function to process packets in real-time.
    It prints TLS-related packets and saves all packets to a PCAP file immediately.
    """
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        ip_src = packet["IP"].src  # Source IP address
        ip_dst = packet["IP"].dst  # Destination IP address
        src_port = packet["TCP"].sport  # Source port
        dst_port = packet["TCP"].dport  # Destination port

        # Save packet immediately to PCAP file
        wrpcap(PCAP_FILE, [packet], append=True)  # Append each packet as it arrives

        # Check if this is HTTPS traffic (Port 443)
        if dst_port == 443 or src_port == 443:
            if packet.haslayer(TLSClientHello):
                handshake = packet[TLSClientHello]
                print(f"[+] TLS ClientHello detected from {ip_src} -> {ip_dst}")

                # Check each attribute of the handshake
                if hasattr(handshake, 'ciphers'):
                    cipher_suites = handshake.ciphers
                    print(f"    Supported Cipher Suites: {', '.join([get_cipher_suite_name(cipher) for cipher in cipher_suites])}")
                if hasattr(handshake, 'version'):
                    print(f"    TLS Version: {get_tls_version(handshake.version)}")
                if hasattr(handshake, 'session_id'):
                    print(f"    Session ID: {handshake.session_id}")
                if hasattr(handshake, 'extensions'):
                    print(f"    Extensions: {handshake.extensions}")
            
            elif packet.haslayer(TLSServerHello):
                handshake = packet[TLSServerHello]
                print(f"[+] TLS ServerHello detected from {ip_src} -> {ip_dst}")

                # Check each attribute of the handshake
                if hasattr(handshake, 'ciphers'):
                    cipher_suites = handshake.ciphers
                    print(f"    Cipher Suite: {', '.join([get_cipher_suite_name(cipher) for cipher in cipher_suites])}")
                if hasattr(handshake, 'version'):
                    print(f"    TLS Version: {get_tls_version(handshake.version)}")

def main():
    """
    Main function to capture network traffic and process TLS packets.
    """
    print("Scapy version: ", scapy.__version__)
    print("Capturing network traffic...")

    # List available interfaces
    interfaces = get_if_list()
    print(f"Available interfaces: {interfaces}")

    # Define the interface to use
    interface = conf.iface
    print(f"Using interface: {interface}")

    # Start capturing traffic and save packets in real-time
    sniff(iface=interface, filter="tcp", prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
