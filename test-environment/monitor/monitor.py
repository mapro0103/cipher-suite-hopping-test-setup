from scapy.all import sniff, load_layer, wrpcap
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import json
import threading
import time
import datetime

# Load the TLS layer in Scapy
load_layer("tls")

# Global counter for iteration
iteration_counter = 0

# File to save packets
PCAP_FILE = "/tmp/scapy_live_capture.pcap"
TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
REPORT_FILE = f"/tmp/tls_report_{TIMESTAMP}.txt"

# Load the permutations JSON file
with open("permutations_5x5.json", "r") as json_file:
    permutations_data = json.load(json_file)

# Cipher Suite Mapping
CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256"
}

CIPHER_MAPPING = {
    0x1301: 'c1',
    0x1302: 'c2',
    0x1303: 'c3',
    0x1304: 'c4',
    0x1305: 'c5'
}

# Global storage for captured sequences
captured_sequences = []
packet_start_times = []
packet_end_times = []
packet_types = []
last_packet_time = time.time()

# Rework to separate signal from packet
def check_timeout():
    """
    Monitors packet capture activity. If no new packet is captured within 3 seconds,
    a report is generated and sequences are processed.
    """
    global captured_sequences, packet_start_times, packet_end_times, packet_types, last_packet_time
    while True:
        time.sleep(5)
        if time.time() - last_packet_time > 3 and captured_sequences:
            generate_report()
            captured_sequences = []  # Reset after timeout
            packet_start_times = []
            packet_end_times = []
            packet_types = []

def extract_cipher_suites(packet):
    """
    Extracts cipher suites from a TLS ClientHello packet and maps them to symbolic representations.
    """
    global captured_sequences, packet_start_times, packet_end_times, packet_types, last_packet_time
    start_time = time.time()
    last_packet_time = start_time
    
    if packet.haslayer(TLS):
        tls_layer = packet[TLS]
        packet_type = tls_layer.msg[0].__class__.__name__ if tls_layer.msg else "Unknown"
        
        if packet.haslayer(TLSClientHello):
            client_hello = packet[TLSClientHello]
            if hasattr(client_hello, 'ciphers'):
                cipher_suites = client_hello.ciphers
                mapped_symbols = [CIPHER_MAPPING[cipher] for cipher in cipher_suites if cipher in CIPHER_MAPPING]
                captured_sequences.append(" ".join(mapped_symbols))
                packet_start_times.append(start_time)
                packet_end_times.append(time.time())
                packet_types.append(packet_type)

def generate_report():
    """
    Generates a text report containing all captured packets, their timestamps, cipher suites, 
    and decoded ASCII message. Also includes packet numbering, total bits, total bytes (converted), 
    and total transmission time.
    """
    
    # Compute covert message before writing the report
    covert_message = ""
    for i in range(0, len(captured_sequences) - 1, 2):
        combined_sequence = " ".join(captured_sequences[i:i+2])
        ascii_value = next((entry["ASCII"] for entry in permutations_data if entry["Permutation"].strip() == combined_sequence.strip()), None)
        decoded_char = chr(ascii_value) if ascii_value is not None else "?"
        covert_message += decoded_char

    # Compute total transmitted bits (4 bits per packet)
    total_bits_transferred = len(packet_types) * 4  

    # Convert bits to bytes
    total_bytes_transferred = total_bits_transferred / 8  

    # Compute total transmission time (first to last packet)
    total_packets = len(packet_types)
    total_time = (packet_end_times[-1] - packet_start_times[0]) if total_packets > 1 else 0
    raw_bandwidth_bits = total_bits_transferred / total_time if total_time > 0 else 0
    raw_bandwidth_bytes = total_bytes_transferred / total_time if total_time > 0 else 0

    with open(REPORT_FILE, "w") as report:
        report.write("TLS Covert Channel Transmission Report\n")
        report.write("====================================\n\n")
        report.write(f"Report Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Total ASCII Data Transferred: {total_bits_transferred} bits ({total_bytes_transferred:.2f} bytes)\n")
        report.write(f"Total Transmission Time: {total_time:.2f} seconds\n")
        report.write(f"Raw Bandwidth: {raw_bandwidth_bits:.2f} bits/second ({raw_bandwidth_bytes:.2f} bytes/second)\n")
        report.write(f"Number of TLS connections: {len(captured_sequences)} \n")

        
        # Write covert message  before captured packets
        report.write("\nCovert Information:\n")
        report.write(covert_message.strip() + "\n\n")
        
        report.write("Captured Packets:\n")

        # Numbering packet pairs
        pair_number = 1
        for i in range(0, len(captured_sequences) - 1, 2):
            report.write(f"\nPacket Pair {pair_number}:\n")
            report.write(f"Cipher Sequence: {captured_sequences[i]} | {captured_sequences[i+1]}\n")
            report.write(f"Packet Type 1: {packet_types[i]}\n")
            report.write(f"Packet 1 Start Time: {packet_start_times[i]:.4f}, End Time: {packet_end_times[i]:.4f}\n")
            report.write(f"Packet Type 2: {packet_types[i+1]}\n")
            report.write(f"Packet 2 Start Time: {packet_start_times[i+1]:.4f}, End Time: {packet_end_times[i+1]:.4f}\n")
            report.write(f"Decoded ASCII Character: {covert_message[pair_number-1]}\n")
            report.write("-----------------------------\n")
            
            pair_number += 1

    print(f"Timeout reached. Report saved to {REPORT_FILE}")

def packet_callback(packet):
    """
    Callback function to process packets in real-time.
    """
    if packet.haslayer(TLSClientHello):
        wrpcap(PCAP_FILE, [packet], append=True)  # Append each packet
        extract_cipher_suites(packet)

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            print(f"TLSClientHello monitored: {src_ip} → {dest_ip}")
        
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
