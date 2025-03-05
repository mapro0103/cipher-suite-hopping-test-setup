from scapy.all import sniff, load_layer, wrpcap
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import json
import threading
import time

# Import ausgelagerte Funktionen aus dem report_generator Modul
from report_generator import generate_report

# Load the TLS layer in Scapy
load_layer("tls")

# Global counter for iteration
iteration_counter = 0

# File to save packets
PCAP_FILE = "/tmp/scapy_live_capture.pcap"

# Load the permutations JSON file
try:
    with open("permutations.json", "r") as json_file:
        permutations_data = json.load(json_file)
    print(f"Loaded {len(permutations_data)} permutation entries")
except Exception as e:
    print(f"Error loading permutations file: {e}")
    permutations_data = []

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

# Special signal ASCII values
SIGNAL_START = "256,256"
SIGNAL_END = "257,257"
SIGNAL_PASSWORD = "258,258"
SIGNAL_RSA = "259,259"
SIGNAL_ECC = "260,260"

# Global storage for captured sequences
captured_sequences = []
packet_start_times = []
packet_end_times = []
packet_types = []
packet_lengths = []  # Added to track raw packet lengths
last_packet_time = time.time()

# Data collection structures
current_data_type = None
current_transmission = []
data_collections = {
    "password": [],
    "rsa": [],
    "ecc": []
}
current_transmission_packets = []

def check_timeout():
    """
    Monitors packet capture activity. If no new packet is captured within 3 seconds,
    a report is generated and sequences are processed.
    Improved to handle partial transmissions better.
    """
    global captured_sequences, packet_start_times, packet_end_times, packet_lengths, packet_types, last_packet_time
    global current_data_type, current_transmission, data_collections, current_transmission_packets
    global show_details
    
    while True:
        time.sleep(3)  # Check every 3 seconds
        
        current_time = time.time()
        if current_time - last_packet_time > 3 and captured_sequences:
            print(f"Timeout detected. Last packet was {current_time - last_packet_time:.2f} seconds ago.")
            
            # Only finish processing if we have an active transmission
            if current_data_type and current_transmission:
                # Make a deep copy of the data
                data_collections[current_data_type].append({
                    "data": list(current_transmission),
                    "packets": list(current_transmission_packets)
                })
                current_transmission = []
                current_transmission_packets = []
                current_data_type = None
            
            # Generate reports for each data type with data
            for data_type in ["password", "rsa", "ecc"]:
                if data_collections[data_type]:
                    print(f"Found {len(data_collections[data_type])} {data_type} transmissions to report.")
                    # Rufen Sie die ausgelagerte Funktion mit allen erforderlichen Argumenten auf
                    generate_report(data_type, data_collections, packet_start_times, packet_end_times, 
                                   packet_types, packet_lengths, captured_sequences, show_details)
            
            # Reset all data only after generating the reports
            captured_sequences = []
            packet_start_times = []
            packet_end_times = []
            packet_types = []
            packet_lengths = []  # Reset packet lengths
            data_collections = {
                "password": [],
                "rsa": [],
                "ecc": []
            }
            current_data_type = None
            current_transmission = []
            current_transmission_packets = []

def extract_cipher_suites(packet):
    """
    Extracts cipher suites from a TLS ClientHello packet and maps them to symbolic representations.
    """
    global captured_sequences, packet_start_times, packet_end_times, packet_types, packet_lengths, last_packet_time
    start_time = time.time()
    last_packet_time = start_time
    
    if packet.haslayer(TLS):
        tls_layer = packet[TLS]
        packet_type = tls_layer.msg[0].__class__.__name__ if tls_layer.msg else "Unknown"
        
        # Store packet length for overt channel measurement
        packet_length = len(bytes(packet))
        
        if packet.haslayer(TLSClientHello):
            client_hello = packet[TLSClientHello]
            if hasattr(client_hello, 'ciphers'):
                cipher_suites = client_hello.ciphers
                mapped_symbols = [CIPHER_MAPPING[cipher] for cipher in cipher_suites if cipher in CIPHER_MAPPING]
                
                # Only append non-empty cipher sequences
                if mapped_symbols:
                    captured_sequences.append(mapped_symbols)
                    packet_start_times.append(start_time)
                    packet_end_times.append(time.time())
                    packet_types.append(packet_type)
                    packet_lengths.append(packet_length)  # Store packet length
                    
                    # After capturing a complete packet, process it with pairs
                    process_captured_packet_pair()
                else:
                    print("Warning: Empty cipher sequence detected and skipped")

def find_matching_ascii_pair(first_list, second_list):
    """
    Find both ASCII values that match the given cipher suite lists.
    Returns a tuple of (first_ascii_value, second_ascii_value) or (None, None) if no match is found.
    """
    for entry in permutations_data:
        if "Permutation" in entry and "ASCII" in entry and len(entry["Permutation"]) == 2:
            perm_first_list = entry["Permutation"][0]
            perm_second_list = entry["Permutation"][1]
            
            # Compare the lists directly
            if perm_first_list == first_list and perm_second_list == second_list:
                # Return both ASCII values as a tuple
                if entry["ASCII"] and len(entry["ASCII"]) >= 2:
                    return (entry["ASCII"][0], entry["ASCII"][1])
                elif entry["ASCII"] and len(entry["ASCII"]) == 1:
                    return (entry["ASCII"][0], None)
    
    return (None, None)

def get_signal_type(first_list, second_list):
    """
    Determine if this packet pair is a control signal.
    Returns signal type as string or None if not a signal.
    """
    ascii_value1, ascii_value2 = find_matching_ascii_pair(first_list, second_list)
    
    if ascii_value1 is None or ascii_value2 is None:
        return None
    
    ascii_pair = f"{ascii_value1},{ascii_value2}"
    
    if ascii_pair == SIGNAL_START:
        return "START"
    elif ascii_pair == SIGNAL_END:
        return "END"
    elif ascii_pair == SIGNAL_PASSWORD:
        return "PASSWORD"
    elif ascii_pair == SIGNAL_RSA:
        return "RSA"
    elif ascii_pair == SIGNAL_ECC:
        return "ECC"
    
    return None  # Regular data packet

def process_captured_packet_pair():
    """
    Process captured sequences in pairs to detect signals and data.
    Fixed version with correct indexing.
    """
    global captured_sequences, current_data_type, current_transmission, current_transmission_packets
    global data_collections
    
    # We need at least 2 packets for a pair
    if len(captured_sequences) < 2:
        return
    
    # Process the latest complete pair
    packet_count = len(captured_sequences)
    if packet_count % 2 == 0:  # We have an even number of packets, can process the last pair
        idx1 = packet_count - 2
        idx2 = packet_count - 1
        
        first_list = captured_sequences[idx1]
        second_list = captured_sequences[idx2]
        
        signal_type = get_signal_type(first_list, second_list)
        
        if signal_type == "START":
            # Start of a new transmission
            current_transmission = []
            current_transmission_packets = []
            # Data type will be set by the next packet pair
        elif signal_type == "END" and current_data_type:
            # End of current transmission
            if current_transmission:
                # Make a deep copy of the data to avoid reference issues
                data_collections[current_data_type].append({
                    "data": list(current_transmission),
                    "packets": list(current_transmission_packets)
                })
            current_transmission = []
            current_transmission_packets = []
            current_data_type = None
        elif signal_type == "PASSWORD":
            current_data_type = "password"
        elif signal_type == "RSA":
            current_data_type = "rsa"
        elif signal_type == "ECC":
            current_data_type = "ecc"
        elif current_data_type:  # Regular data packet in an active transmission
            # Get the ASCII values for this pair
            ascii_value1, ascii_value2 = find_matching_ascii_pair(first_list, second_list)
            
            if ascii_value1 is not None and ascii_value2 is not None:
                # Add to current transmission
                current_transmission.append((ascii_value1, ascii_value2))
                # Store actual packet indices instead of relative ones
                current_transmission_packets.append((idx1, idx2))

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

def parse_arguments():
    """Parse command line arguments."""
    import argparse
    
    parser = argparse.ArgumentParser(description="TLS Covert Channel Monitor")
    parser.add_argument("--details", action="store_true", 
                        help="Include detailed packet information in reports")
    
    return parser.parse_args()

def main():
    """Main function to start monitoring."""
    global show_details
    
    args = parse_arguments()
    show_details = args.details
    
    print("Starting TLS Covert Channel Monitor...")
    if show_details:
        print("Detailed packet information will be included in reports.")
    else:
        print("Only summary information will be included in reports.")
    
    start_sniffing()

if __name__ == "__main__":
    # Global flag for detailed reports
    show_details = False
    main()