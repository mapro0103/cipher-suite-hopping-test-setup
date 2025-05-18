#!/usr/bin/env python3
import os
import sys
from collections import Counter, defaultdict
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import rdpcap, load_layer
from scapy.layers.tls.extensions import TLS_Ext_SupportedVersions
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.record import TLS
import hashlib
from scipy.stats import entropy

# Load the TLS layer in Scapy
load_layer("tls")

def extract_cipher_suites(pcap_file):
    """
    Extract cipher suite lists from TLS 1.3 ClientHello messages in a PCAP file.
    
    Args:
        pcap_file (str): Path to the PCAP file
    
    Returns:
        list: List of tuples (client_ip, cipher_suites)
    """
    print(f"Loading PCAP file: {pcap_file}")
    packets = rdpcap(pcap_file)
    cipher_lists = []
    
    for packet in packets:
        if TLS in packet and packet.haslayer(TLSClientHello):
            client_hello = packet[TLSClientHello]
            src_ip = packet.src if hasattr(packet, 'src') else "unknown"
            cipher_suites = tuple(client_hello.ciphers)
            cipher_lists.append((src_ip, cipher_suites))
    
    print(f"Found {len(cipher_lists)} TLS ClientHello messages")
    return cipher_lists

def analyze_cipher_diversity(cipher_lists):
    """
    Analyze the diversity of cipher suite orders.
    
    Args:
        cipher_lists (list): List of (client_ip, cipher_suites) tuples
    
    Returns:
        dict: Dictionary containing diversity metrics
    """
    # Count unique cipher suite lists
    cipher_counts = Counter(cs for _, cs in cipher_lists)
    
    # Get unique cipher suite orderings
    unique_orders = list(cipher_counts.keys())
    
    # Calculate frequency of each ordering
    total = len(cipher_lists)
    frequencies = {order: count/total for order, count in cipher_counts.items()}
    
    # Calculate entropy as a measure of randomness
    probs = np.array(list(frequencies.values()))
    shannon_entropy = entropy(probs, base=2)
    
    # Group by client IP to see if different clients have different preferences
    ip_to_ciphers = defaultdict(list)
    for ip, cs in cipher_lists:
        ip_to_ciphers[ip].append(cs)
    
    return {
        "total_samples": total,
        "unique_orders": len(unique_orders),
        "most_common": cipher_counts.most_common(5),
        "entropy": shannon_entropy,
        "ip_diversity": len(ip_to_ciphers),
        "cipher_counts": cipher_counts
    }

def create_visualizations(pcap1_analysis, pcap2_analysis, pcap1_name, pcap2_name):
    """
    Create visualizations comparing the two PCAP files.
    
    Args:
        pcap1_analysis (dict): Analysis results for the first PCAP
        pcap2_analysis (dict): Analysis results for the second PCAP
        pcap1_name (str): Name of the first PCAP file
        pcap2_name (str): Name of the second PCAP file
    """
    # Set up the figure
    plt.figure(figsize=(15, 12))
    
    # 1. Bar chart of unique cipher suite orders
    plt.subplot(2, 2, 1)
    data = [pcap1_analysis["unique_orders"], pcap2_analysis["unique_orders"]]
    plt.bar([pcap1_name, pcap2_name], data, color=['skyblue', 'orange'])
    plt.title('Number of Unique Cipher Suite Orders')
    plt.ylabel('Count')
    plt.xticks(rotation=30)
    
    # 2. Entropy comparison
    plt.subplot(2, 2, 2)
    data = [pcap1_analysis["entropy"], pcap2_analysis["entropy"]]
    plt.bar([pcap1_name, pcap2_name], data, color=['skyblue', 'orange'])
    plt.title('Shannon Entropy of Cipher Suite Orders')
    plt.ylabel('Entropy (bits)')
    plt.xticks(rotation=30)
    
    # 3. Distribution of top cipher suite orders
    plt.subplot(2, 2, 3)
    
    # For the first PCAP
    top_orders1 = [hash_cipher_suite(cs) for cs, _ in pcap1_analysis["most_common"][:5]]
    counts1 = [count for _, count in pcap1_analysis["most_common"][:5]]
    
    # For the second PCAP
    top_orders2 = [hash_cipher_suite(cs) for cs, _ in pcap2_analysis["most_common"][:5]]
    counts2 = [count for _, count in pcap2_analysis["most_common"][:5]]
    
    # Plot
    x = np.arange(5)
    width = 0.35
    plt.bar(x - width/2, counts1, width, label=pcap1_name)
    plt.bar(x + width/2, counts2, width, label=pcap2_name)
    plt.xlabel('Top 5 Cipher Suite Orders (Hashed)')
    plt.ylabel('Count')
    plt.title('Distribution of Top Cipher Suite Orders')
    plt.xticks(x, [o[:6] + '...' for o in top_orders1], rotation=45)
    plt.legend()
    
    # 4. CDF of cipher suite order frequencies
    plt.subplot(2, 2, 4)
    
    # Calculate CDFs
    def calculate_cdf(counts):
        total = sum(counts.values())
        sorted_counts = sorted(counts.values(), reverse=True)
        cdf = np.cumsum(sorted_counts) / total
        return cdf
    
    cdf1 = calculate_cdf(pcap1_analysis["cipher_counts"])
    cdf2 = calculate_cdf(pcap2_analysis["cipher_counts"])
    
    plt.plot(range(1, len(cdf1) + 1), cdf1, 'b-', label=pcap1_name)
    plt.plot(range(1, len(cdf2) + 1), cdf2, 'r-', label=pcap2_name)
    plt.xlabel('Number of Different Cipher Suite Orders')
    plt.ylabel('Cumulative Probability')
    plt.title('CDF of Cipher Suite Order Distribution')
    plt.legend()
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('tls_cipher_suite_comparison.png')
    plt.close()
    
    # 5. Create a heatmap of cipher suite frequencies (separate figure)
    create_cipher_heatmap(pcap1_analysis, pcap2_analysis, pcap1_name, pcap2_name)

def hash_cipher_suite(cipher_suite):
    """Create a hash representation of a cipher suite tuple for display purposes"""
    return hashlib.md5(str(cipher_suite).encode()).hexdigest()

def create_cipher_heatmap(pcap1_analysis, pcap2_analysis, pcap1_name, pcap2_name):
    """Create a heatmap comparing the frequency of specific cipher suites in each position"""
    # This is a more complex visualization showing position-specific differences
    # We'll need to process the cipher suites to extract positional information
    
    plt.figure(figsize=(14, 10))
    
    # Find all unique cipher suites across both PCAPs
    all_ciphers = set()
    max_length = 0
    
    for cs_tuple, _ in pcap1_analysis["cipher_counts"].items():
        all_ciphers.update(cs_tuple)
        max_length = max(max_length, len(cs_tuple))
    
    for cs_tuple, _ in pcap2_analysis["cipher_counts"].items():
        all_ciphers.update(cs_tuple)
        max_length = max(max_length, len(cs_tuple))
    
    # Limit to the most common cipher suites for clarity
    if len(all_ciphers) > 20:
        # Count occurrences of each cipher across all positions
        cipher_occurrences = Counter()
        for cs_tuple, count in pcap1_analysis["cipher_counts"].items():
            for cipher in cs_tuple:
                cipher_occurrences[cipher] += count
        
        for cs_tuple, count in pcap2_analysis["cipher_counts"].items():
            for cipher in cs_tuple:
                cipher_occurrences[cipher] += count
        
        # Keep only the top 20 most common ciphers
        all_ciphers = set([cipher for cipher, _ in cipher_occurrences.most_common(20)])
    
    # Convert cipher suites to integers for better display
    cipher_to_idx = {cipher: i for i, cipher in enumerate(sorted(all_ciphers))}
    
    # Create position matrices for both PCAPs
    def create_position_matrix(cipher_counts):
        matrix = np.zeros((len(all_ciphers), min(10, max_length)))
        total_samples = sum(cipher_counts.values())
        
        for cs_tuple, count in cipher_counts.items():
            for pos, cipher in enumerate(cs_tuple[:10]):  # Limit to first 10 positions
                if cipher in all_ciphers:
                    matrix[cipher_to_idx[cipher], pos] += count
        
        # Normalize by total samples
        return matrix / total_samples
    
    matrix1 = create_position_matrix(pcap1_analysis["cipher_counts"])
    matrix2 = create_position_matrix(pcap2_analysis["cipher_counts"])
    
    # Calculate the difference matrix
    diff_matrix = matrix1 - matrix2
    
    # Plot heatmaps side by side
    plt.subplot(3, 1, 1)
    sns.heatmap(matrix1, cmap="YlGnBu", vmin=0, vmax=max(matrix1.max(), matrix2.max()),
                xticklabels=range(1, min(11, max_length+1)),
                yticklabels=[f"0x{cipher:04x}" for cipher in sorted(all_ciphers)])
    plt.title(f'{pcap1_name} Cipher Positions')
    plt.xlabel('Position in ClientHello')
    plt.ylabel('Cipher Suite')
    
    plt.subplot(3, 1, 2)
    sns.heatmap(matrix2, cmap="YlGnBu", vmin=0, vmax=max(matrix1.max(), matrix2.max()),
                xticklabels=range(1, min(11, max_length+1)),
                yticklabels=[f"0x{cipher:04x}" for cipher in sorted(all_ciphers)])
    plt.title(f'{pcap2_name} Cipher Positions')
    plt.xlabel('Position in ClientHello')
    plt.ylabel('Cipher Suite')
    
    plt.subplot(3, 1, 3)
    sns.heatmap(diff_matrix, cmap="RdBu_r", vmin=-1, vmax=1,
                xticklabels=range(1, min(11, max_length+1)),
                yticklabels=[f"0x{cipher:04x}" for cipher in sorted(all_ciphers)])
    plt.title('Difference in Cipher Positions')
    plt.xlabel('Position in ClientHello')
    plt.ylabel('Cipher Suite')
    
    plt.tight_layout()
    plt.savefig('tls_cipher_suite_heatmap.png')
    plt.close()

def analyze_random_vs_static(pcap1_data, pcap2_data, pcap1_name, pcap2_name):
    """
    Analyze and visualize the difference between random and static cipher suite orders
    
    Args:
        pcap1_data (list): Cipher suite lists from first PCAP
        pcap2_data (list): Cipher suite lists from second PCAP
    """
    # Extract just the cipher suites
    cipher_lists1 = [cs for _, cs in pcap1_data]
    cipher_lists2 = [cs for _, cs in pcap2_data]
    
    # Calculate statistics
    unique_ratio1 = len(set(cipher_lists1)) / len(cipher_lists1) if cipher_lists1 else 0
    unique_ratio2 = len(set(cipher_lists2)) / len(cipher_lists2) if cipher_lists2 else 0
    
    # Calculate Jaccard similarity for consecutive cipher lists
    def calc_jaccard_similarities(cipher_lists):
        if len(cipher_lists) <= 1:
            return []
        
        similarities = []
        for i in range(len(cipher_lists) - 1):
            set1 = set(cipher_lists[i])
            set2 = set(cipher_lists[i + 1])
            similarity = len(set1.intersection(set2)) / len(set1.union(set2))
            similarities.append(similarity)
        
        return similarities
    
    # Calculate position-wise consistency
    def calc_position_consistency(cipher_lists):
        if not cipher_lists:
            return []
        
        # Find the maximum length
        max_len = max(len(cs) for cs in cipher_lists)
        
        # Calculate consistency for each position
        consistencies = []
        for pos in range(max_len):
            values = [cs[pos] if pos < len(cs) else None for cs in cipher_lists]
            counter = Counter(values)
            most_common = counter.most_common(1)[0][1] if counter else 0
            consistency = most_common / len(values)
            consistencies.append(consistency)
        
        return consistencies
    
    similarities1 = calc_jaccard_similarities(cipher_lists1)
    similarities2 = calc_jaccard_similarities(cipher_lists2)
    
    position_consistency1 = calc_position_consistency(cipher_lists1)
    position_consistency2 = calc_position_consistency(cipher_lists2)
    
    # Create visualizations
    plt.figure(figsize=(15, 10))
    
    # 1. Unique cipher suite order ratio
    plt.subplot(2, 2, 1)
    plt.bar([pcap1_name, pcap2_name], [unique_ratio1, unique_ratio2], color=['skyblue', 'orange'])
    plt.title('Unique Cipher Suite Order Ratio')
    plt.ylabel('Unique Orders / Total Orders')
    plt.grid(axis='y')
    
    # 2. Jaccard similarity distribution
    plt.subplot(2, 2, 2)
    plt.hist(similarities1, alpha=0.5, bins=20, label=pcap1_name)
    plt.hist(similarities2, alpha=0.5, bins=20, label=pcap2_name)
    plt.title('Jaccard Similarity Between Consecutive ClientHellos')
    plt.xlabel('Similarity')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(True)
    
    # 3. Position consistency
    plt.subplot(2, 2, 3)
    x = range(1, min(10, len(position_consistency1) + 1))
    plt.plot(x, position_consistency1[:10], 'o-', label=pcap1_name)
    plt.plot(x, position_consistency2[:10], 'o-', label=pcap2_name)
    plt.title('Cipher Suite Position Consistency')
    plt.xlabel('Position in ClientHello')
    plt.ylabel('Consistency (0-1)')
    plt.legend()
    plt.grid(True)
    
    # 4. Order stability over time
    plt.subplot(2, 2, 4)
    
    # Create a simplified hash for each cipher suite list
    def hash_order(cs):
        return hashlib.md5(str(cs).encode()).hexdigest()[:8]
    
    hashes1 = [hash_order(cs) for cs in cipher_lists1[:100]]  # Limit to first 100 for clarity
    hashes2 = [hash_order(cs) for cs in cipher_lists2[:100]]
    
    # Map hashes to integers for plotting
    unique_hashes1 = list(set(hashes1))
    unique_hashes2 = list(set(hashes2))
    
    hash_to_int1 = {h: i for i, h in enumerate(unique_hashes1)}
    hash_to_int2 = {h: i for i, h in enumerate(unique_hashes2)}
    
    y1 = [hash_to_int1[h] for h in hashes1]
    y2 = [hash_to_int2[h] for h in hashes2]
    
    plt.plot(range(len(y1)), y1, 'o-', alpha=0.5, label=pcap1_name)
    plt.plot(range(len(y2)), y2, 'o-', alpha=0.5, label=pcap2_name)
    plt.title('Cipher Suite Order Stability Over Time')
    plt.xlabel('ClientHello Sequence')
    plt.ylabel('Order Hash (mapped to integers)')
    plt.legend()
    plt.grid(True)
    
    plt.tight_layout()
    plt.savefig('tls_cipher_suite_randomness.png')
    plt.close()

def main():
    if len(sys.argv) != 3:
        print("Usage: python tls_cipher_analysis.py <pcap1> <pcap2>")
        print("  pcap1: PCAP file with varying cipher suite orders")
        print("  pcap2: PCAP file with consistent cipher suite orders")
        sys.exit(1)
    
    pcap1_file = sys.argv[1]
    pcap2_file = sys.argv[2]
    
    # Extract names from file paths
    pcap1_name = os.path.basename(pcap1_file).split('.')[0]
    pcap2_name = os.path.basename(pcap2_file).split('.')[0]
    
    # Extract cipher suites from both PCAP files
    pcap1_data = extract_cipher_suites(pcap1_file)
    pcap2_data = extract_cipher_suites(pcap2_file)
    
    # Analyze cipher diversity
    pcap1_analysis = analyze_cipher_diversity(pcap1_data)
    pcap2_analysis = analyze_cipher_diversity(pcap2_data)
    
    # Print key statistics
    print("\n--- TLS 1.3 Cipher Suite Order Analysis ---")
    print(f"\n{pcap1_name} (Variable Orders):")
    print(f"  Total ClientHello messages: {pcap1_analysis['total_samples']}")
    print(f"  Unique cipher suite orders: {pcap1_analysis['unique_orders']}")
    print(f"  Order entropy: {pcap1_analysis['entropy']:.4f} bits")
    print(f"  Unique client IPs: {pcap1_analysis['ip_diversity']}")
    
    print(f"\n{pcap2_name} (Consistent Orders):")
    print(f"  Total ClientHello messages: {pcap2_analysis['total_samples']}")
    print(f"  Unique cipher suite orders: {pcap2_analysis['unique_orders']}")
    print(f"  Order entropy: {pcap2_analysis['entropy']:.4f} bits")
    print(f"  Unique client IPs: {pcap2_analysis['ip_diversity']}")
    
    # Create visualizations
    print("\nCreating visualizations...")
    create_visualizations(pcap1_analysis, pcap2_analysis, pcap1_name, pcap2_name)
    analyze_random_vs_static(pcap1_data, pcap2_data, pcap1_name, pcap2_name)
    
    print("\nAnalysis complete. Output files:")
    print("  - tls_cipher_suite_comparison.png")
    print("  - tls_cipher_suite_heatmap.png")
    print("  - tls_cipher_suite_randomness.png")

if __name__ == "__main__":
    main()
