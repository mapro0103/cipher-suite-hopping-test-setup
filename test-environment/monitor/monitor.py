import scapy
from scapy.all import sniff, conf, get_if_list, load_layer
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello

# Load the TLS layer in Scapy
load_layer("tls")

# Complete Cipher Suites Mapping for TLS 1.2 and TLS 1.3 based on IANA TLS parameters
# https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4

# Complete Cipher Suites Mapping for TLS 1.2 and TLS 1.3 based on IANA TLS parameters

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
    0x000D: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",  # 13
    0x0010: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",  # 16
    0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",  # 19
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",  # 22
    0x0030: "TLS_DH_DSS_WITH_AES_128_CBC_SHA",  # 48
    0x0031: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",  # 49
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",  # 50
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",  # 51
    0x0036: "TLS_DH_DSS_WITH_AES_256_CBC_SHA",  # 54
    0x0037: "TLS_DH_RSA_WITH_AES_256_CBC_SHA",  # 55
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",  # 56
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",  # 57
    0x003E: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",  # 62
    0x003F: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",  # 63
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",  # 64
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",  # 103
    0x0068: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",  # 104
    0x0069: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",  # 105
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",  # 106
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",  # 107
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",  # 24
    0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",  # 27
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",  # 52
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",  # 58
    0x006C: "TLS_DH_anon_WITH_AES_128_CBC_SHA256",  # 108
    0x006D: "TLS_DH_anon_WITH_AES_256_CBC_SHA256",  # 109
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",  # 49391
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",  # 49392
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",  # 49391
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",  # 49392
    0xC024: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",  # 49384
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",  # 49384
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",  # 156
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",  # 157
    0xC02B: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",  # 49387
    0xC02C: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",  # 49388

    # TLS 1.3 Cipher Suites
    0x1301: "TLS_AES_128_GCM_SHA256",  # 49313
    0x1302: "TLS_AES_256_GCM_SHA384",  # 49314
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",  # 49315
    0x1304: "TLS_AES_128_CCM_SHA256",  # 49316
    0x1305: "TLS_AES_256_CCM_SHA384",  # 49317
}

# Dictionary to map TLS version numbers to human-readable names
TLS_VERSIONS = {
    0x301: "TLS 1.0",   # 769
    0x302: "TLS 1.1",   # 770
    0x303: "TLS 1.2",   # 771
    0x304: "TLS 1.3"    # 772
}

# Function to map cipher suite id to human-readable name
def get_cipher_suite_name(cipher_id):
    return CIPHER_SUITES.get(cipher_id, f"Unknown Cipher Suite: {cipher_id}")

# Function to map TLS version to human-readable name
def get_tls_version(version):
    return TLS_VERSIONS.get(version, f"Unknown TLS Version: {version}")

def packet_callback(packet):
    if packet.haslayer("IP") and packet.haslayer("TCP"):
        ip_src = packet["IP"].src  # Source IP address
        ip_dst = packet["IP"].dst  # Destination IP address
        src_port = packet["TCP"].sport  # Source port
        dst_port = packet["TCP"].dport  # Destination port
        
        # Check if this is HTTPS traffic (Port 443)
        if dst_port == 443 or src_port == 443:
            # Check for TLS handshake packets
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
            # else:
            #     print(f"[+] Intercepted packet: {ip_src} -> {ip_dst} (Non-Handshake TLS traffic)")

def main():
    print("I am monitor.py")
    print("Scapy version: ", scapy.__version__)
    print("Capturing network traffic...")

    # List available interfaces
    interfaces = get_if_list()
    print(f"Available interfaces: {interfaces}")

    # Define the interface to use
    interface = conf.iface
    print(f"Using interface: {interface}")

    # Start capturing traffic
    sniff(iface=interface, filter="tcp", prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
