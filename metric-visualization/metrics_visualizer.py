#!/usr/bin/env python3
"""
TLS Covert Channel Metrics Visualizer (Updated)

This script reads metrics files from the same directory and creates visualizations focused on:
1. Bandwidth comparison between data types
2. Box plot for bandwidth
3. Bar chart with error bars for bandwidth
4. Analysis of covert data length to overt data length ratio
5. Checking for transmission errors in covert messages
"""

import os
import json
import glob
import argparse
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime
import re

def load_metrics_files(directory="."):
    """
    Load all metrics files from the directory.
    
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
    Load the original data files (not the metrics files).
    
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
    Aggregate metrics from multiple files of the same data type.
    
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
    
    # Combine data from all metrics files
    for metrics in metrics_list:
        aggregated["num_transmissions"] += metrics["num_transmissions"]
        aggregated["total_bits"] += metrics["total_bits"]
        aggregated["total_bytes"] += metrics["total_bytes"]
        aggregated["total_transmission_time"] += metrics["total_transmission_time"]
        aggregated["total_connections"] += metrics["total_connections"]
        
        if "total_overt_bits" in metrics:
            aggregated["total_overt_bits"] += metrics["total_overt_bits"]
        if "total_overt_bytes" in metrics:
            aggregated["total_overt_bytes"] += metrics["total_overt_bytes"]
        
        # Extend arrays of individual measurements
        aggregated["transmission_times"].extend(metrics["transmission_times"])
        aggregated["transmission_sizes"].extend(metrics["transmission_sizes"])
        aggregated["data_rates"].extend(metrics["data_rates"])
        aggregated["connections_per_transmission"].extend(metrics["connections_per_transmission"])
        
        if "overt_message_sizes" in metrics:
            aggregated["overt_message_sizes"].extend(metrics["overt_message_sizes"])
            
        # Extract covert messages if available
        if "transmissions" in metrics:
            for transmission in metrics["transmissions"]:
                if "covert_message" in transmission:
                    aggregated["covert_messages"].append(transmission["covert_message"])
    
    # Calculate average bandwidth
    if aggregated["total_transmission_time"] > 0:
        aggregated["avg_bandwidth_bits"] = aggregated["total_bits"] / aggregated["total_transmission_time"]
        aggregated["avg_bandwidth_bytes"] = aggregated["total_bytes"] / aggregated["total_transmission_time"]
    else:
        aggregated["avg_bandwidth_bits"] = 0
        aggregated["avg_bandwidth_bytes"] = 0
    
    # Calculate covert to overt ratio if overt data is available
    if aggregated["total_overt_bits"] > 0:
        aggregated["covert_to_overt_ratio"] = aggregated["total_bits"] / aggregated["total_overt_bits"]
    else:
        aggregated["covert_to_overt_ratio"] = 0
    
    # Calculate aggregated statistics
    aggregated["stats"] = {
        "time": {
            "mean": np.mean(aggregated["transmission_times"]) if aggregated["transmission_times"] else 0,
            "std": np.std(aggregated["transmission_times"]) if aggregated["transmission_times"] else 0,
            "min": np.min(aggregated["transmission_times"]) if aggregated["transmission_times"] else 0,
            "max": np.max(aggregated["transmission_times"]) if aggregated["transmission_times"] else 0
        },
        "size": {
            "mean": np.mean(aggregated["transmission_sizes"]) if aggregated["transmission_sizes"] else 0,
            "std": np.std(aggregated["transmission_sizes"]) if aggregated["transmission_sizes"] else 0,
            "min": np.min(aggregated["transmission_sizes"]) if aggregated["transmission_sizes"] else 0,
            "max": np.max(aggregated["transmission_sizes"]) if aggregated["transmission_sizes"] else 0
        },
        "rate": {
            "mean": np.mean(aggregated["data_rates"]) if aggregated["data_rates"] else 0,
            "std": np.std(aggregated["data_rates"]) if aggregated["data_rates"] else 0,
            "min": np.min(aggregated["data_rates"]) if aggregated["data_rates"] else 0,
            "max": np.max(aggregated["data_rates"]) if aggregated["data_rates"] else 0
        },
        "connections": {
            "mean": np.mean(aggregated["connections_per_transmission"]) if aggregated["connections_per_transmission"] else 0,
            "std": np.std(aggregated["connections_per_transmission"]) if aggregated["connections_per_transmission"] else 0,
            "min": np.min(aggregated["connections_per_transmission"]) if aggregated["connections_per_transmission"] else 0,
            "max": np.max(aggregated["connections_per_transmission"]) if aggregated["connections_per_transmission"] else 0
        }
    }
    
    if aggregated["overt_message_sizes"]:
        aggregated["stats"]["overt_size"] = {
            "mean": np.mean(aggregated["overt_message_sizes"]),
            "std": np.std(aggregated["overt_message_sizes"]),
            "min": np.min(aggregated["overt_message_sizes"]),
            "max": np.max(aggregated["overt_message_sizes"])
        }
    
    return aggregated

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
            if aggregated:
                data_types.append(data_type.upper())
                bandwidths.append(aggregated["avg_bandwidth_bits"])
                std_devs.append(aggregated["stats"]["rate"]["std"])
    
    if not data_types:
        print("No data available for bandwidth comparison")
        return
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(data_types, bandwidths, yerr=std_devs, capsize=10, alpha=0.7)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + std_devs[bars.index(bar)],
                 f'{height:.2f}',
                 ha='center', va='bottom')
    
    plt.title('Bandwidth Comparison by Data Type')
    plt.xlabel('Data Type')
    plt.ylabel('Bandwidth (bits/second)')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/bandwidth_comparison.svg."
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Bandwidth comparison chart saved to {output_file}")
    plt.close()

def plot_bandwidth_boxplot(metrics_by_type, output_dir="."):
    """
    Create a box plot comparing bandwidth distribution across different data types.
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
    
    plt.figure(figsize=(10, 6))
    box = plt.boxplot(data_for_boxplot, labels=labels, patch_artist=True)
    
    # Add some color
    colors = ['lightblue', 'lightgreen', 'lightpink']
    for patch, color in zip(box['boxes'], colors[:len(box['boxes'])]):
        patch.set_facecolor(color)
    
    plt.title('Bandwidth Distribution by Data Type')
    plt.xlabel('Data Type')
    plt.ylabel('Bandwidth (bits/second)')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/bandwidth_boxplot.svg"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Bandwidth boxplot saved to {output_file}")
    plt.close()

def plot_covert_overt_ratio(metrics_by_type, output_dir="."):
    """
    Create a bar chart comparing the ratio of covert data size to overt data size.
    """
    data_types = []
    ratios = []
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and hasattr(aggregated, "covert_to_overt_ratio"):
                data_types.append(data_type.upper())
                ratios.append(aggregated["covert_to_overt_ratio"] * 100)  # Convert to percentage
    
    if not data_types:
        print("No data available for covert to overt ratio comparison")
        return
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(data_types, ratios, alpha=0.7)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.4f}%',
                 ha='center', va='bottom')
    
    plt.title('Covert to Overt Data Ratio')
    plt.xlabel('Data Type')
    plt.ylabel('Ratio (%) of Covert Bits to Overt Bits')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/covert_overt_ratio.svg"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Covert to overt ratio chart saved to {output_file}")
    plt.close()

def check_transmission_errors(metrics_by_type, original_data_by_type, output_dir="."):
    """
    Check for transmission errors by comparing original data with received data.
    Includes a success percentage for each data type.
    """
    error_report = []
    
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
        error_report.append(f"\n==== TRANSMISSION ERROR CHECK FOR {data_type.upper()} ====")
        
        if len(original_messages) != len(received_messages):
            error_report.append(f"Message count mismatch: {len(original_messages)} original vs {len(received_messages)} received")
        
        success_count = 0
        total_compared = min(len(original_messages), len(received_messages))
        
        for i, (orig, recv) in enumerate(zip(original_messages, received_messages)):
            # Remove any trailing whitespace for comparison
            orig = orig.strip()
            recv = recv.strip()
            
            if orig == recv:
                success_count += 1
                error_report.append(f"Transmission {i+1}: SUCCESS - Messages match")
            else:
                error_report.append(f"Transmission {i+1}: ERROR - Messages do not match")
                # Calculate how many characters are different
                min_len = min(len(orig), len(recv))
                diff_count = sum(1 for a, b in zip(orig, recv) if a != b)
                diff_count += abs(len(orig) - len(recv))
                error_rate = (diff_count / max(len(orig), len(recv))) * 100
                error_report.append(f"  - Error rate: {error_rate:.2f}% ({diff_count} characters different)\n  - Original message:\n{orig}\n  - Received message:\n{recv}")
        
        # Calculate and add success percentage
        if total_compared > 0:
            success_percentage = (success_count / total_compared) * 100
            error_report.append(f"\nSUCCESS RATE FOR {data_type.upper()}: {success_percentage:.2f}% ({success_count}/{total_compared} messages matched successfully)")
    
    # Write the error report to a file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/transmission_errors.txt"
    with open(output_file, 'w') as f:
        f.write('\n'.join(error_report))
    
    print(f"Transmission error report saved to {output_file}")
    
    # Also print to console
    for line in error_report:
        print(line)

def plot_all_metrics(metrics_by_type, original_data_by_type, output_dir="."):
    """Plot all requested metrics visualizations."""
    plot_bandwidth_comparison(metrics_by_type, output_dir)
    plot_bandwidth_boxplot(metrics_by_type, output_dir)
    plot_covert_overt_ratio(metrics_by_type, output_dir)
    check_transmission_errors(metrics_by_type, original_data_by_type, output_dir)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="TLS Covert Channel Metrics Visualizer")
    parser.add_argument("--output-dir", type=str, default=".",
                        help="Directory where to save the visualization files (default: current directory)")
    parser.add_argument("--metric", type=str, 
                        choices=["bandwidth", "boxplot", "ratio", "errors", "all"],
                        default="all", help="Specific metric to visualize (default: all)")
    
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Setup directories
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load metrics files from current directory
    print("Looking for metrics files in current directory...")
    metrics_by_type = load_metrics_files(".")
    
    # Load original data files from current directory
    print("Looking for original data files in current directory...")
    original_data_by_type = load_original_data_files(".")
    
    # Check if we have any data
    if not any(metrics_by_type.values()):
        print("No metrics files found in current directory")
        return
    
    # Print summary of available data
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            print(f"Found {len(metrics_list)} metrics files for {data_type}")
    
    for data_type, data_list in original_data_by_type.items():
        if data_list:
            print(f"Found {len(data_list)} original data entries for {data_type}")
    
    # Plot requested metrics
    if args.metric == "all":
        plot_all_metrics(metrics_by_type, original_data_by_type, args.output_dir)
    elif args.metric == "bandwidth":
        plot_bandwidth_comparison(metrics_by_type, args.output_dir)
    elif args.metric == "boxplot":
        plot_bandwidth_boxplot(metrics_by_type, args.output_dir)
    elif args.metric == "ratio":
        plot_covert_overt_ratio(metrics_by_type, args.output_dir)
    elif args.metric == "errors":
        check_transmission_errors(metrics_by_type, original_data_by_type, args.output_dir)
        
    print(f"Analysis complete. Results saved to {args.output_dir}")

if __name__ == "__main__":
    main()