#!/usr/bin/env python3
"""
Enhanced TLS Covert Channel Metrics Visualizer

This script efficiently processes JSON metrics files for password, RSA, and ECC data types to visualize:
1. Effective bandwidth (bits/second) with statistical distribution analysis
2. Covert-to-overt data ratio analysis
3. Transmission reliability through bit-accurate comparisons
"""

import os
import json
import glob
import argparse
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime

def load_metrics_files(directory="."):
    """
    Load all metrics files from the directory, avoiding recalculation of data already in JSONs.
    
    Returns:
        dict: Dictionary with data types as keys and list of metric files as values
    """
    metrics_files = glob.glob(f"{directory}/metrics_*.json")
    metrics_by_type = {
        "password": [],
        "rsa": [],
        "ecc": []
    }
    
    for file_path in metrics_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                data_type = data.get('data_type')
                if data_type in metrics_by_type:
                    metrics_by_type[data_type].append(data)
        except Exception as e:
            print(f"Error loading {file_path}: {e}")
    
    return metrics_by_type

def load_original_data_files(directory="."):
    """
    Load the original data files for comparison with transmitted data.
    
    Returns:
        dict: Dictionary with data types as keys and list of data files as values
    """
    data_types = ["password", "rsa", "ecc"]
    data_by_type = {data_type: [] for data_type in data_types}
    
    for data_type in data_types:
        data_files = glob.glob(f"{directory}/{data_type}_*.json")
        
        for file_path in data_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if item.get('data_type') == data_type:
                                data_by_type[data_type].append(item)
                    else:
                        if data.get('data_type') == data_type:
                            data_by_type[data_type].append(data)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
    
    return data_by_type

def aggregate_metrics(metrics_list):
    """
    Efficiently aggregate metrics from multiple files of the same data type,
    using pre-calculated values where available.
    
    Args:
        metrics_list: List of metrics dictionaries
        
    Returns:
        dict: Aggregated metrics
    """
    if not metrics_list:
        return None
    
    # Initialize aggregated metrics
    aggregated = {
        "data_type": metrics_list[0]["data_type"],
        "num_transmissions": 0,
        "total_bits": 0,
        "total_bytes": 0,
        "total_transmission_time": 0,
        "total_connections": 0,
        "total_overt_bits": 0,
        "total_overt_bytes": 0,
        "transmission_times": [],
        "transmission_sizes": [],
        "overt_message_sizes": [],
        "data_rates": [],
        "connections_per_transmission": [],
        "covert_messages": []
    }
    
    # Combine data from all metrics files, using existing calculations when available
    for metrics in metrics_list:
        # Directly use counters from metrics files
        aggregated["num_transmissions"] += metrics.get("num_transmissions", 0)
        aggregated["total_bits"] += metrics.get("total_bits", 0)
        aggregated["total_bytes"] += metrics.get("total_bytes", 0)
        aggregated["total_transmission_time"] += metrics.get("total_transmission_time", 0)
        aggregated["total_connections"] += metrics.get("total_connections", 0)
        aggregated["total_overt_bits"] += metrics.get("total_overt_bits", 0)
        aggregated["total_overt_bytes"] += metrics.get("total_overt_bytes", 0)
        
        # Extend arrays of individual measurements
        if "transmission_times" in metrics:
            aggregated["transmission_times"].extend(metrics["transmission_times"])
        if "transmission_sizes" in metrics:
            aggregated["transmission_sizes"].extend(metrics["transmission_sizes"])
        if "data_rates" in metrics:
            aggregated["data_rates"].extend(metrics["data_rates"])
        if "connections_per_transmission" in metrics:
            aggregated["connections_per_transmission"].extend(metrics["connections_per_transmission"])
        if "overt_message_sizes" in metrics:
            aggregated["overt_message_sizes"].extend(metrics["overt_message_sizes"])
            
        # Extract covert messages for transmission reliability checking
        if "transmissions" in metrics:
            for transmission in metrics["transmissions"]:
                if "covert_message" in transmission:
                    aggregated["covert_messages"].append(transmission["covert_message"])
    
    # Only calculate bandwidth if not already provided in metrics
    if "avg_bandwidth_bits" not in aggregated and aggregated["total_transmission_time"] > 0:
        aggregated["avg_bandwidth_bits"] = aggregated["total_bits"] / aggregated["total_transmission_time"]
        aggregated["avg_bandwidth_bytes"] = aggregated["total_bytes"] / aggregated["total_transmission_time"]
    
    # Calculate covert to overt ratio if not already provided
    if "covert_to_overt_ratio" not in aggregated and aggregated["total_overt_bits"] > 0:
        aggregated["covert_to_overt_ratio"] = aggregated["total_bits"] / aggregated["total_overt_bits"]
    
    # Calculate statistical metrics for bandwidth analysis
    aggregated["stats"] = {
        "rate": {
            "mean": np.mean(aggregated["data_rates"]) if aggregated["data_rates"] else 0,
            "std": np.std(aggregated["data_rates"]) if aggregated["data_rates"] else 0,
            "min": np.min(aggregated["data_rates"]) if aggregated["data_rates"] else 0,
            "max": np.max(aggregated["data_rates"]) if aggregated["data_rates"] else 0
        }
    }
    
    return aggregated

################################# Diagrams #################################


def plot_bandwidth_comparison(metrics_by_type, output_dir="."):
    """
    Create a bar chart comparing bandwidth across different data types with error bars.
    """
    data_types = []
    bandwidths = []
    std_devs = []
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and "avg_bandwidth_bits" in aggregated:
                data_types.append(data_type.upper())
                bandwidths.append(aggregated["avg_bandwidth_bits"])
                std_devs.append(aggregated["stats"]["rate"]["std"])
    
    if not data_types:
        print("No data available for bandwidth comparison")
        return
    
    x_pos = np.arange(len(data_types))
    plt.figure(figsize=(5, 7))
    bars = plt.bar(data_types, bandwidths, yerr=std_devs, capsize=10, alpha=0.7, color=['#4285F4', '#34A853', '#FBBC05'], width=0.35)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height() + 4
        plt.text(bar.get_x() + bar.get_width()/2., height + std_devs[bars.index(bar)],
                 f'{height:.2f}',
                 ha='center', va='bottom', fontsize=12)
    
    plt.title('Effective Bandwidth Comparison by Data Type', fontsize=14, fontweight='bold')
    plt.xlabel('Data Type', fontsize=12)
    plt.ylabel('Bandwidth (bits/second)', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(x_pos, fontsize=12)
    
    # Save the figure
    output_file = f"{output_dir}/bandwidth_comparison.svg"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Bandwidth comparison chart saved to {output_file}")
    plt.close()

def plot_bandwidth_boxplot(metrics_by_type, output_dir="."):
    """
    Create a box plot showing bandwidth distribution across different data types.
    """
    data_for_boxplot = []
    labels = []
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and aggregated["data_rates"]:
                data_for_boxplot.append(aggregated["data_rates"])
                labels.append(data_type.upper())
    
    if not data_for_boxplot:
        print("No data available for bandwidth boxplot")
        return
    
    plt.figure(figsize=(7, 7))
    box = plt.boxplot(data_for_boxplot, labels=labels, patch_artist=True, widths=0.25)
    
    # Add color to boxplots
    colors = ['#4285F4', '#34A853', '#FBBC05']
    for patch, color in zip(box['boxes'], colors[:len(box['boxes'])]):
        patch.set_facecolor(color)
        patch.set_alpha(0.7) 
    
    # Add statistical annotations
    for i, data in enumerate(data_for_boxplot):
        if data:
            # Calculate the right edge of each boxplot
            box_width = 0.2  # Standard width of boxplot
            box_right_edge = i + 1 + (box_width/2)
            
            # Add a small offset from the edge
            text_x_position = box_right_edge + 0.1
            
            plt.text(text_x_position, np.median(data),
                    f'Median: {np.median(data):.2f}\nMean: {np.mean(data):.2f}\nStd: {np.std(data):.2f}',
                    verticalalignment='center', fontsize=12)
    
    plt.title('Bandwidth Statistical Distribution by Data Type', fontsize=14, fontweight='bold')
    plt.xlabel('Data Type', fontsize=12)
    plt.ylabel('Bandwidth (bits/second)', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(fontsize=12)
    
    # Save the figure
    output_file = f"{output_dir}/bandwidth_boxplot.svg"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Bandwidth boxplot saved to {output_file}")
    plt.close()

def plot_covert_overt_ratio(metrics_by_type, output_dir="."):
    """
    Create a bar chart showing the ratio of covert data size to overt data size.
    """
    data_types = []
    ratios = []
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and "covert_to_overt_ratio" in aggregated:
                data_types.append(data_type.upper())
                ratios.append(aggregated["covert_to_overt_ratio"] * 100)  # Convert to percentage
    
    if not data_types:
        print("No data available for covert to overt ratio comparison")
        return
    
    plt.figure(figsize=(6, 7))
    bars = plt.bar(data_types, ratios, alpha=0.7, color=['#4285F4', '#34A853', '#FBBC05'], width=0.35)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.003,
                 f'{height:.4f}%',
                 ha='center', va='bottom', fontsize=12)
    
    plt.title('Covert-to-Overt Data Ratio', fontsize=14, fontweight='bold')
    plt.xlabel('Data Type', fontsize=12)
    plt.ylabel('Ratio (%) of Covert Bits to Overt Bits', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(fontsize=12)
    
    # Save the figure
    output_file = f"{output_dir}/covert_overt_ratio.svg"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Covert to overt ratio chart saved to {output_file}")
    plt.close()

def analyze_transmission_reliability(metrics_by_type, original_data_by_type, output_dir="."):
    """
    Analyze transmission reliability by comparing original data with received data.
    Creates a detailed report and visualization of reliability metrics.
    """
    error_report = []
    reliability_data = []
    
    for data_type, metrics_list in metrics_by_type.items():
        original_list = original_data_by_type.get(data_type, [])
        
        if not metrics_list or not original_list:
            error_report.append(f"No data available for {data_type}")
            continue
        
        # Get received messages
        aggregated = aggregate_metrics(metrics_list)
        received_messages = aggregated.get("covert_messages", [])
        
        # Get original messages
        original_messages = []
        for item in original_list:
            if "covert_message" in item:
                original_messages.append(item["covert_message"])
        
        # Compare messages
        error_report.append(f"\n==== TRANSMISSION RELIABILITY ANALYSIS FOR {data_type.upper()} ====")
        
        if len(original_messages) != len(received_messages):
            error_report.append(f"Message count mismatch: {len(original_messages)} original vs {len(received_messages)} received")
        
        success_count = 0
        total_compared = min(len(original_messages), len(received_messages))
        bit_accuracy = []
        
        for i, (orig, recv) in enumerate(zip(original_messages, received_messages)):
            # Remove any trailing whitespace for comparison
            orig = orig.strip()
            recv = recv.strip()
            
            if orig == recv:
                success_count += 1
                error_report.append(f"Transmission {i+1}: SUCCESS - Messages match")
                bit_accuracy.append(100.0)
            else:
                # Calculate bit-accurate comparison
                min_len = min(len(orig), len(recv))
                diff_count = sum(1 for a, b in zip(orig, recv) if a != b)
                diff_count += abs(len(orig) - len(recv))
                max_len = max(len(orig), len(recv))
                
                accuracy = ((max_len - diff_count) / max_len) * 100
                bit_accuracy.append(accuracy)
                
                error_report.append(f"Transmission {i+1}: PARTIAL - Messages differ")
                error_report.append(f"  - Bit accuracy: {accuracy:.2f}% ({max_len - diff_count}/{max_len} characters matched)")
        
        # Calculate and add success percentage
        if total_compared > 0:
            success_percentage = (success_count / total_compared) * 100
            avg_bit_accuracy = np.mean(bit_accuracy) if bit_accuracy else 0
            
            error_report.append(f"\nRELIABILITY METRICS FOR {data_type.upper()}:")
            error_report.append(f"- Perfect transmission rate: {success_percentage:.2f}% ({success_count}/{total_compared})")
            error_report.append(f"- Average bit accuracy: {avg_bit_accuracy:.2f}%")
            
            reliability_data.append({
                "data_type": data_type,
                "perfect_rate": success_percentage,
                "bit_accuracy": avg_bit_accuracy
            })
    
    # Write the error report to a file
    output_file = f"{output_dir}/transmission_reliability.txt"
    with open(output_file, 'w') as f:
        f.write('\n'.join(error_report))
    
    print(f"Transmission reliability report saved to {output_file}")
    
    # Create reliability visualization
    if reliability_data:
        plot_reliability_metrics(reliability_data, output_dir)
    
    return reliability_data

def plot_reliability_metrics(reliability_data, output_dir="."):
    """
    Create a dual-axis bar chart showing perfect transmission rate and bit accuracy.
    """
    plt.figure(figsize=(8, 7))
    data_types = [item["data_type"].upper() for item in reliability_data]
    perfect_rates = [item["perfect_rate"] for item in reliability_data]
    bit_accuracies = [item["bit_accuracy"] for item in reliability_data]
    
    ax1 = plt.subplot(111)
    # Leave more space at the bottom for the legend
    plt.subplots_adjust(bottom=0.15)
    
    bars1 = ax1.bar([i-0.15 for i in range(len(data_types))], perfect_rates, width=0.3,
                   color='#4285F4', label='Perfect Transmission Rate', alpha=0.7)
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{height:.1f}%', ha='center', va='bottom', fontsize=12)
    
    bars2 = ax1.bar([i+0.2 for i in range(len(data_types))], bit_accuracies, width=0.3,
                   color='#34A853', label='Bit-level Accuracy', alpha=0.7)
    for bar in bars2:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{height:.1f}%', ha='center', va='bottom', fontsize=12)
    
    plt.title('Data Transmission Reliability', fontsize=14, fontweight='bold')
    plt.xlabel('Data Type', fontsize=12)
    plt.ylabel('Percentage (%)', fontsize=12)
       
    # Add legend at the bottom, centered below x-axis
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1), ncol=2, fontsize=12)
    
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.xticks(range(len(data_types)), data_types, fontsize=12)
    plt.ylim(0, 110)
    
    # Save the figure
    output_file = f"{output_dir}/transmission_reliability.svg"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Transmission reliability chart saved to {output_file}")
    plt.close()

def create_consolidated_report(metrics_by_type, reliability_data, output_dir="."):
    """
    Create a consolidated report with all key metrics.
    """
    report = ["# TLS COVERT CHANNEL PERFORMANCE ANALYSIS", ""]
    
    # Bandwidth metrics
    report.append("## 1. Effective Bandwidth Analysis")
    
    bandwidth_table = ["| Data Type | Avg. Bandwidth (bits/s) | Min | Max | Std Dev |", "| --------- | ---------------------- | --- | --- | ------- |"]
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and "avg_bandwidth_bits" in aggregated:
                stats = aggregated["stats"]["rate"]
                bandwidth_table.append(f"| {data_type.upper()} | {aggregated['avg_bandwidth_bits']:.2f} | {stats['min']:.2f} | {stats['max']:.2f} | {stats['std']:.2f} |")
    
    report.extend(bandwidth_table)
    report.append("")
    
    # Covert-to-overt ratio
    report.append("## 2. Covert-to-Overt Data Ratio")
    
    ratio_table = ["| Data Type | Covert:Overt Ratio (%) |", "| --------- | --------------------- |"]
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and "covert_to_overt_ratio" in aggregated:
                ratio = aggregated["covert_to_overt_ratio"] * 100
                ratio_table.append(f"| {data_type.upper()} | {ratio:.4f}% |")
    
    report.extend(ratio_table)
    report.append("")
    
    # Transmission reliability
    report.append("## 3. Transmission Reliability")
    
    if reliability_data:
        reliability_table = ["| Data Type | Perfect Transmission Rate | Bit-level Accuracy |", "| --------- | ------------------------- | ----------------- |"]
        
        for item in reliability_data:
            reliability_table.append(f"| {item['data_type'].upper()} | {item['perfect_rate']:.2f}% | {item['bit_accuracy']:.2f}% |")
        
        report.extend(reliability_table)
    else:
        report.append("No reliability data available.")
    
    # Write the report to a file
    output_file = f"{output_dir}/consolidated_report.md"
    with open(output_file, 'w') as f:
        f.write('\n'.join(report))
    
    print(f"Consolidated report saved to {output_file}")

def run_all_analyses(metrics_by_type, original_data_by_type, output_dir="."):
    """Run all requested analyses."""
    print("Analyzing effective bandwidth...")
    plot_bandwidth_comparison(metrics_by_type, output_dir)
    plot_bandwidth_boxplot(metrics_by_type, output_dir)
    
    print("Analyzing covert-to-overt ratio...")
    plot_covert_overt_ratio(metrics_by_type, output_dir)
    
    print("Analyzing transmission reliability...")
    reliability_data = analyze_transmission_reliability(metrics_by_type, original_data_by_type, output_dir)
    
    print("Creating consolidated report...")
    create_consolidated_report(metrics_by_type, reliability_data, output_dir)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Enhanced TLS Covert Channel Metrics Visualizer")
    parser.add_argument("--output-dir", type=str, default="./output",
                        help="Directory where to save the visualization files (default: ./output)")
    parser.add_argument("--metric", type=str, 
                        choices=["bandwidth", "ratio", "reliability", "all"],
                        default="all", help="Specific metric to analyze (default: all)")
    
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Setup output directory
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load metrics files from current directory
    print("Loading metrics files...")
    metrics_by_type = load_metrics_files(".")
    
    # Load original data files for reliability analysis
    print("Loading original data files...")
    original_data_by_type = load_original_data_files(".")
    
    # Check if we have any data
    if not any(metrics_by_type.values()):
        print("No metrics files found in current directory")
        return
    
    # Print summary of available data
    print("\nData available for analysis:")
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            print(f"- {data_type.upper()}: {len(metrics_list)} metrics files")
    
    for data_type, data_list in original_data_by_type.items():
        if data_list:
            print(f"- {data_type.upper()}: {len(data_list)} original data entries")
    
    # Run requested analyses
    if args.metric == "all":
        run_all_analyses(metrics_by_type, original_data_by_type, args.output_dir)
    elif args.metric == "bandwidth":
        plot_bandwidth_comparison(metrics_by_type, args.output_dir)
        plot_bandwidth_boxplot(metrics_by_type, args.output_dir)
    elif args.metric == "ratio":
        plot_covert_overt_ratio(metrics_by_type, args.output_dir)
    elif args.metric == "reliability":
        reliability_data = analyze_transmission_reliability(metrics_by_type, original_data_by_type, args.output_dir)
        
    print(f"\nAnalysis complete. Results saved to {args.output_dir}")

if __name__ == "__main__":
    main()