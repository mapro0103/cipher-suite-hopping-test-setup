from scapy.all import sniff, load_layer, wrpcap, rdpcap
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import gc
import json
import threading
import time
import os

from report_generator import generate_report

# Load the TLS layer in Scapy
load_layer("tls")

# Global counter for iteration
iteration_counter = 0

# File to save packets
PCAP_FILE = "/tmp/scapy_live_capture.pcap"

# Global variables for storing permutation data
permutations_data = []
permutation_lookup = {}  # New lookup dictionary for efficient searches

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
packet_types = []
packet_lengths = []  # Added to track raw packet lengths
last_packet_time = time.time()
analysis_in_progress = False
# packet_sequence_numbers = {}  # Dict for packets to sequence numbers assignment
# next_sequence_number = 0 
# processed_sequences = set()

# Data collection structures
current_data_type = None
current_transmission = []
data_collections = {
    "password": [],
    "rsa": [],
    "ecc": []
}
current_transmission_packets = []

def load_permutations():
    """
    Loads the permutations from JSON file and creates an efficient lookup dictionary.
    """
    global permutations_data, permutation_lookup
    
    try:
        with open("permutations.json", "r") as json_file:
            permutations_data = json.load(json_file)
        
        # Create lookup dictionary for efficient search
        for entry in permutations_data:
            if "Permutation" in entry and "ASCII" in entry and len(entry["Permutation"]) == 2:
                # Convert lists to tuples as dictionary keys (immutable)
                key = (tuple(entry["Permutation"][0]), tuple(entry["Permutation"][1]))
                
                # Store ASCII values
                if entry["ASCII"] and len(entry["ASCII"]) >= 2:
                    permutation_lookup[key] = (entry["ASCII"][0], entry["ASCII"][1])
                elif entry["ASCII"] and len(entry["ASCII"]) == 1:
                    permutation_lookup[key] = (entry["ASCII"][0], None)
        
        print(f"Created lookup dictionary with {len(permutation_lookup)} entries")
        permutations_data = []
        gc.collect()
    except Exception as e:
        print(f"Error loading permutations file: {e}")
        permutations_data = []
        permutation_lookup = {}

def analyze_pcap():
    """
    Analyze the PCAP file after timeout instead of analyzing packets on the fly.
    """
    global captured_sequences, packet_start_times, packet_lengths, packet_types, show_details
    global current_data_type, current_transmission, data_collections, current_transmission_packets
    try:
        # Reset all data collections for clean analysis
        captured_sequences = []
        packet_start_times = []
        packet_types = []
        packet_lengths = []
        
        # Add handshake counter
        handshake_count = 0
        
        # Load packets from PCAP file
        packets = rdpcap(PCAP_FILE)
        print(f"Loaded {len(packets)} packets from PCAP file for analysis")
        
        # Calculate time span for handshakes per second
        if len(packets) > 1:
            first_timestamp = float(packets[0].time)
            last_timestamp = float(packets[-1].time)
            time_span = last_timestamp - first_timestamp
        else:
            time_span = 1  # Default to 1 second if only one packet
        
        # First pass: extract all TLSClientHello packets and their cipher suites
        for packet in packets:
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]
                packet_type = tls_layer.msg[0].__class__.__name__ if tls_layer.msg else "Unknown"
                # Store packet length for overt channel measurement
                packet_length = len(bytes(packet))
                packet_timestamp = float(packet.time)
                
                if packet.haslayer(TLSClientHello):
                    # Count handshake
                    handshake_count += 1
                    
                    client_hello = packet[TLSClientHello]
                    if hasattr(client_hello, 'ciphers'):
                        cipher_suites = client_hello.ciphers
                        mapped_symbols = [CIPHER_MAPPING[cipher] for cipher in cipher_suites if cipher in CIPHER_MAPPING]
                        # Only append non-empty cipher sequences
                        if mapped_symbols:
                            captured_sequences.append(mapped_symbols)
                            packet_start_times.append(packet_timestamp)
                            packet_types.append(packet_type)
                            packet_lengths.append(packet_length) # Store packet length
                        else:
                            print("Warning: Empty cipher sequence detected and skipped")
                            
        # Second pass: process all packets in pairs
        process_all_packet_pairs()
        
        # Generate reports for each data type with data
        for data_type in ["password", "rsa", "ecc"]:
            if data_collections[data_type]:
                print(f"Found {len(data_collections[data_type])} {data_type} transmissions to report.")
                # Call the report generation function with all required arguments
                generate_report(data_type, data_collections, packet_start_times,
                               packet_types, packet_lengths, captured_sequences, show_details)
                               
        # Reset data collections after report generation
        reset_data_collections()
        
        # Calculate and display handshakes per second
        if time_span > 0:
            handshakes_per_second = handshake_count / time_span
        else:
            handshakes_per_second = handshake_count
            
        # Display handshake statistics
        print(f"\nHandshake Statistics:")
        print(f"Total Handshakes: {handshake_count}")
        print(f"Time Span: {time_span:.2f} seconds")
        print(f"Handshakes/Second: {handshakes_per_second:.2f}")
        
        # Reset PCAP file for next capture session
        open(PCAP_FILE, 'wb').close()
        
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")

def find_matching_ascii_pair(first_list, second_list):
    """
    Find both ASCII values that match the given cipher suite lists using the lookup dictionary.
    Returns a tuple of (first_ascii_value, second_ascii_value) or (None, None) if no match is found.
    """
    # Convert lists to tuples for dictionary key lookup
    key = (tuple(first_list), tuple(second_list))
    
    # Direct dictionary lookup (O(1) operation instead of O(n))
    return permutation_lookup.get(key, (None, None))

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

def process_all_packet_pairs():
    """
    Process all captured sequences in pairs to detect signals and data.
    This processes all the data from the PCAP file at once.
    """
    global captured_sequences, current_data_type, current_transmission, current_transmission_packets
    global data_collections
    
    # Reset data collections before processing
    current_data_type = None
    current_transmission = []
    current_transmission_packets = []
    data_collections = {
        "password": [],
        "rsa": [],
        "ecc": []
    }
    
    # We need at least 2 packets for a pair
    if len(captured_sequences) < 2:
        return
    
    # Process all pairs in sequence
    for i in range(0, len(captured_sequences) - 1, 2):
        idx1 = i
        idx2 = i + 1
        
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
                # Store actual packet indices
                current_transmission_packets.append((idx1, idx2))

def reset_data_collections():
    """
    Reset all data collections after analysis.
    """
    global captured_sequences, packet_start_times, packet_types, packet_lengths
    global current_data_type, current_transmission, data_collections, current_transmission_packets
    
    captured_sequences = []
    packet_start_times = []
    packet_types = []
    packet_lengths = []
    data_collections = {
        "password": [],
        "rsa": [],
        "ecc": []
    }
    current_data_type = None
    current_transmission = []
    current_transmission_packets = []

def check_timeout():
    global last_packet_time
    global analysis_in_progress
    
    while True:
        time.sleep(3)  # Check every 3 seconds
        current_time = time.time()
        if current_time - last_packet_time > 3 and not analysis_in_progress:
            if os.path.exists(PCAP_FILE) and os.path.getsize(PCAP_FILE) > 0:
                analysis_in_progress = True
                print(f"Analyzing PCAP file....")
                analyze_pcap()
                print(f"Analysis finished!")
                analysis_in_progress = False
                # Update last packet time to avoid repeated processing
                last_packet_time = current_time

def packet_callback(packet):
    """
    Callback function to process packets in real-time.
    Only saves packets to PCAP file without analyzing them.
    """
    global last_packet_time
    
    if packet.haslayer(TLSClientHello):
        wrpcap(PCAP_FILE, [packet], append=True)  # Append each packet
        last_packet_time = time.time()

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            # print(f"TLSClientHello monitored: {src_ip} → {dest_ip}")
        
def start_sniffing():
    """
    Starts sniffing network traffic and saves TLS packets to PCAP file.
    """
    print("Starting sniffing on network interface...")
    
    # Ensure PCAP file is empty at start
    open(PCAP_FILE, 'wb').close()
    
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
    
    # Load permutations and create efficient lookup dictionary
    load_permutations()
    
    if show_details:
        print("Detailed packet information will be included in reports.")
    else:
        print("Only summary information will be included in reports.")
    
    start_sniffing()

if __name__ == "__main__":
    # Global flag for detailed reports
    show_details = False
    main()