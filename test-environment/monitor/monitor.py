from scapy.all import sniff, load_layer, wrpcap
from scapy.layers.inet import IP
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import json
import threading
import time
import datetime
import os

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
    """
    global captured_sequences, packet_start_times, packet_end_times, packet_types, last_packet_time
    global current_data_type, current_transmission, data_collections, current_transmission_packets
    
    while True:
        time.sleep(3)  # Check every 3 seconds
        
        current_time = time.time()
        if current_time - last_packet_time > 3 and captured_sequences:
            print(f"Timeout detected. Last packet was {current_time - last_packet_time:.2f} seconds ago.")
            
            # Finish processing any pending transmission
            if current_data_type and current_transmission:
                data_collections[current_data_type].append({
                    "data": current_transmission,
                    "packets": current_transmission_packets
                })
                current_transmission = []
                current_transmission_packets = []
                current_data_type = None
            
            # Generate reports for each data type
            for data_type in ["password", "rsa", "ecc"]:
                if data_collections[data_type]:
                    print(f"Found {len(data_collections[data_type])} {data_type} transmissions to report.")
                    generate_report(data_type)
            
            # Reset all data
            captured_sequences = []
            packet_start_times = []
            packet_end_times = []
            packet_types = []
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
                
                # Only append non-empty cipher sequences
                if mapped_symbols:
                    captured_sequences.append(mapped_symbols)
                    packet_start_times.append(start_time)
                    packet_end_times.append(time.time())
                    packet_types.append(packet_type)
                    
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
                data_collections[current_data_type].append({
                    "data": current_transmission,
                    "packets": current_transmission_packets
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
                current_transmission_packets.append((idx1, idx2))

def generate_report(data_type):
    """
    Generates a text report for a specific data type, containing all captured packets,
    their timestamps, cipher suites, and decoded ASCII message.
    """
    global show_details
    
    if not data_collections[data_type]:
        print(f"No {data_type} transmissions to report")
        return
    
    TIMESTAMP = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    REPORT_FILE = f"/tmp/tls_report_{data_type}_{TIMESTAMP}.txt"
    
    try:
        with open(REPORT_FILE, "w") as report:
            report.write(f"TLS Covert Channel Transmission Report - {data_type.upper()}\n")
            report.write("====================================\n\n")
            report.write(f"Report Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report.write(f"Data Type: {data_type.upper()}\n")
            report.write(f"Number of Transmissions: {len(data_collections[data_type])}\n\n")
            
            # Calculate aggregate statistics first
            total_bits = 0
            total_transmission_time = 0
            total_pairs = 0
            total_chars = 0
            total_connections = 0
            
            # For statistical analysis
            data_rates = []
            transmission_times = []
            transmission_sizes = []
            connections_per_transmission = []
            
            # First pass to calculate aggregate statistics
            for transmission in data_collections[data_type]:
                data = transmission["data"]
                packets = transmission["packets"]
                
                if not data or not packets:
                    continue
                
                # Count connections (packet pairs) in this transmission
                connections_count = len(packets)
                connections_per_transmission.append(connections_count)
                total_connections += connections_count
                
                first_packet_idx = packets[0][0]
                last_packet_idx = packets[-1][1]
                
                start_time = packet_start_times[first_packet_idx]
                end_time = packet_end_times[last_packet_idx]
                transmission_time = end_time - start_time
                total_transmission_time += transmission_time
                transmission_times.append(transmission_time)
                
                pairs_count = len(data)
                total_pairs += pairs_count
                trans_chars = pairs_count * 2  # Each pair has 2 ASCII chars
                total_chars += trans_chars
                trans_total_bits = trans_chars * 8
                total_bits += trans_total_bits
                transmission_sizes.append(trans_total_bits)
                
                # Calculate data rate for this transmission
                if transmission_time > 0:
                    data_rate = trans_total_bits / transmission_time
                    data_rates.append(data_rate)
            
            # Calculate statistical values
            import numpy as np
            
            # For transmission times
            mean_time = np.mean(transmission_times) if transmission_times else 0
            std_time = np.std(transmission_times) if transmission_times else 0
            min_time = np.min(transmission_times) if transmission_times else 0
            max_time = np.max(transmission_times) if transmission_times else 0
            
            # For transmission sizes
            mean_size = np.mean(transmission_sizes) if transmission_sizes else 0
            std_size = np.std(transmission_sizes) if transmission_sizes else 0
            min_size = np.min(transmission_sizes) if transmission_sizes else 0
            max_size = np.max(transmission_sizes) if transmission_sizes else 0
            
            # For data rates
            mean_rate = np.mean(data_rates) if data_rates else 0
            std_rate = np.std(data_rates) if data_rates else 0
            min_rate = np.min(data_rates) if data_rates else 0
            max_rate = np.max(data_rates) if data_rates else 0
            
            # For connections per transmission
            mean_connections = np.mean(connections_per_transmission) if connections_per_transmission else 0
            std_connections = np.std(connections_per_transmission) if connections_per_transmission else 0
            min_connections = np.min(connections_per_transmission) if connections_per_transmission else 0
            max_connections = np.max(connections_per_transmission) if connections_per_transmission else 0
            
            # Write the aggregate statistics at the top
            total_bytes = total_bits / 8
            report.write("Aggregated Statistics:\n")
            report.write(f"Total ASCII Data Transferred: {total_bits} bits ({total_bytes:.2f} bytes)\n")
            report.write(f"Total Character Pairs: {total_pairs} ({total_chars} characters)\n")
            report.write(f"Total Transmission Time: {total_transmission_time:.2f} seconds\n")
            report.write(f"Total TLS Connections: {total_connections}\n")
            
            if total_transmission_time > 0:
                avg_bandwidth_bits = total_bits / total_transmission_time
                avg_bandwidth_bytes = total_bytes / total_transmission_time
                report.write(f"Average Bandwidth: {avg_bandwidth_bits:.2f} bits/second ({avg_bandwidth_bytes:.2f} bytes/second)\n\n")
            
            # Scientific Statistical Analysis
            num_transmissions = len(data_collections[data_type])
            report.write("Statistical Analysis:\n")
            report.write(f"Number of Transmissions: {num_transmissions}\n\n")
            
            # Format function for consistency
            def format_stat(name, value, precision=2):
                return f"{name:20s}: {value:.{precision}f}"
            
            # Transmission Times
            report.write("Transmission Times (seconds):\n")
            report.write(f"{format_stat('Mean', mean_time)}\n")
            report.write(f"{format_stat('Std Deviation', std_time)}\n")
            report.write(f"{format_stat('Minimum', min_time)}\n")
            report.write(f"{format_stat('Maximum', max_time)}\n\n")
            
            # Transmission Sizes
            report.write("Transmission Sizes (bits):\n")
            report.write(f"{format_stat('Mean', mean_size)}\n")
            report.write(f"{format_stat('Mean (bytes)', mean_size/8)}\n")
            report.write(f"{format_stat('Std Deviation', std_size)}\n")
            report.write(f"{format_stat('Minimum', min_size)}\n")
            report.write(f"{format_stat('Maximum', max_size)}\n\n")
            
            # Data Rates
            report.write("Data Transfer Rates (bits/second):\n")
            report.write(f"{format_stat('Mean', mean_rate)}\n")
            report.write(f"{format_stat('Mean (bytes/sec)', mean_rate/8)}\n")
            report.write(f"{format_stat('Std Deviation', std_rate)}\n")
            report.write(f"{format_stat('Minimum', min_rate)}\n")
            report.write(f"{format_stat('Maximum', max_rate)}\n\n")
            
            # Connections per Transmission
            report.write("TLS Connections per Transmission:\n")
            report.write(f"{format_stat('Total', total_connections)}\n")
            report.write(f"{format_stat('Mean', mean_connections)}\n")
            report.write(f"{format_stat('Std Deviation', std_connections)}\n")
            report.write(f"{format_stat('Minimum', min_connections)}\n")
            report.write(f"{format_stat('Maximum', max_connections)}\n\n")
            
            # Process each transmission
            for trans_idx, transmission in enumerate(data_collections[data_type], 1):
                data = transmission["data"]
                packets = transmission["packets"]
                
                if not data or not packets:
                    continue
                
                # Calculate transmission statistics
                first_packet_idx = packets[0][0]
                last_packet_idx = packets[-1][1]
                
                start_time = packet_start_times[first_packet_idx]
                end_time = packet_end_times[last_packet_idx]
                transmission_time = end_time - start_time
                
                total_chars = len(data) * 2  # Each pair has 2 ASCII chars
                trans_total_bits = total_chars * 8
                trans_total_bytes = trans_total_bits / 8
                
                bandwidth_bits = trans_total_bits / transmission_time if transmission_time > 0 else 0
                bandwidth_bytes = trans_total_bytes / transmission_time if transmission_time > 0 else 0
                
                report.write(f"Transmission #{trans_idx}:\n")
                report.write(f"  Start Time: {datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
                report.write(f"  End Time: {datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
                report.write(f"  Duration: {transmission_time:.4f} seconds\n")
                report.write(f"  Data: {trans_total_bits} bits ({trans_total_bytes:.2f} bytes)\n")
                report.write(f"  Bandwidth: {bandwidth_bits:.2f} bits/second ({bandwidth_bytes:.2f} bytes/second)\n\n")
                
                # Decode and display the message
                covert_message = ""
                for ascii1, ascii2 in data:
                    covert_message += chr(ascii1) + chr(ascii2)
                
                report.write(f"  Decoded Message:\n{covert_message}\n\n")
                
                # Detailed packet information only if --details flag is set
                if show_details:
                    report.write("  Captured Packets:\n")
                    
                    for pair_idx, (idx1, idx2) in enumerate(packets, 1):
                        ascii1, ascii2 = data[pair_idx - 1]
                        report.write(f"    Packet Pair {pair_idx}:\n")
                        report.write(f"      Cipher Sequence 1: {', '.join(captured_sequences[idx1])}\n")
                        report.write(f"      Cipher Sequence 2: {', '.join(captured_sequences[idx2])}\n")
                        report.write(f"      Packet Type 1: {packet_types[idx1]}\n")
                        report.write(f"      Packet 1 Start Time: {packet_start_times[idx1]:.4f}, End Time: {packet_end_times[idx1]:.4f}\n")
                        report.write(f"      Packet Type 2: {packet_types[idx2]}\n")
                        report.write(f"      Packet 2 Start Time: {packet_start_times[idx2]:.4f}, End Time: {packet_end_times[idx2]:.4f}\n")
                        report.write(f"      Decoded ASCII Characters: '{chr(ascii1)}' ({ascii1}), '{chr(ascii2)}' ({ascii2})\n")
                        report.write("      -----------------------------\n")
                
                report.write("\n")
            
            # No need for total statistics here as we moved them to the top
        
        print(f"Report for {data_type} data saved to {REPORT_FILE}")
        # Verify the file was created
        if os.path.exists(REPORT_FILE):
            print(f"Report file exists: {REPORT_FILE}")
            print(f"Report file size: {os.path.getsize(REPORT_FILE)} bytes")
        else:
            print(f"WARNING: Report file was not created: {REPORT_FILE}")
    except Exception as e:
        print(f"Error creating report for {data_type}: {e}")

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