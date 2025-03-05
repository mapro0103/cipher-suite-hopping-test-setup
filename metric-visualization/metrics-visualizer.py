#!/usr/bin/env python3
"""
TLS Covert Channel Metrics Visualizer

This script reads metrics files from the same directory and creates
comparative visualizations between different data types (password, RSA, ECC).
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
    Load all metrics files from the current directory.
    
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
        "transmission_times": [],
        "transmission_sizes": [],
        "data_rates": [],
        "connections_per_transmission": []
    }
    
    # Combine data from all metrics files
    for metrics in metrics_list:
        aggregated["num_transmissions"] += metrics["num_transmissions"]
        aggregated["total_bits"] += metrics["total_bits"]
        aggregated["total_bytes"] += metrics["total_bytes"]
        aggregated["total_transmission_time"] += metrics["total_transmission_time"]
        aggregated["total_connections"] += metrics["total_connections"]
        
        # Extend arrays of individual measurements
        aggregated["transmission_times"].extend(metrics["transmission_times"])
        aggregated["transmission_sizes"].extend(metrics["transmission_sizes"])
        aggregated["data_rates"].extend(metrics["data_rates"])
        aggregated["connections_per_transmission"].extend(metrics["connections_per_transmission"])
    
    # Calculate average bandwidth
    if aggregated["total_transmission_time"] > 0:
        aggregated["avg_bandwidth_bits"] = aggregated["total_bits"] / aggregated["total_transmission_time"]
        aggregated["avg_bandwidth_bytes"] = aggregated["total_bytes"] / aggregated["total_transmission_time"]
    else:
        aggregated["avg_bandwidth_bits"] = 0
        aggregated["avg_bandwidth_bytes"] = 0
    
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
    
    return aggregated

def plot_bandwidth_comparison(metrics_by_type, output_dir="."):
    """
    Create a bar chart comparing bandwidth across different data types.
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
    output_file = f"{output_dir}/bandwidth_comparison_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Bandwidth comparison chart saved to {output_file}")
    plt.close()

def plot_transmission_time_comparison(metrics_by_type, output_dir="."):
    """
    Create a box plot comparing transmission times across different data types.
    """
    data_for_boxplot = []
    labels = []
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and aggregated["transmission_times"]:
                data_for_boxplot.append(aggregated["transmission_times"])
                labels.append(data_type.upper())
    
    if not data_for_boxplot:
        print("No data available for transmission time comparison")
        return
    
    plt.figure(figsize=(10, 6))
    box = plt.boxplot(data_for_boxplot, labels=labels, patch_artist=True)
    
    # Add some color
    colors = ['lightblue', 'lightgreen', 'lightpink']
    for patch, color in zip(box['boxes'], colors[:len(box['boxes'])]):
        patch.set_facecolor(color)
    
    plt.title('Transmission Time Comparison by Data Type')
    plt.xlabel('Data Type')
    plt.ylabel('Transmission Time (seconds)')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/transmission_time_comparison_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Transmission time comparison chart saved to {output_file}")
    plt.close()

def plot_connections_per_bit(metrics_by_type, output_dir="."):
    """
    Create a bar chart comparing the number of connections needed per bit transmitted.
    """
    data_types = []
    connections_per_bit = []
    
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            aggregated = aggregate_metrics(metrics_list)
            if aggregated and aggregated["total_bits"] > 0:
                data_types.append(data_type.upper())
                conn_per_bit = aggregated["total_connections"] / aggregated["total_bits"]
                connections_per_bit.append(conn_per_bit)
    
    if not data_types:
        print("No data available for connections per bit comparison")
        return
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(data_types, connections_per_bit, alpha=0.7)
    
    # Add values on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                 f'{height:.4f}',
                 ha='center', va='bottom')
    
    plt.title('TLS Connections per Bit Comparison')
    plt.xlabel('Data Type')
    plt.ylabel('Connections per Bit')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Save the figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/connections_per_bit_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Connections per bit chart saved to {output_file}")
    plt.close()

def plot_data_rate_distribution(metrics_by_type, output_dir="."):
    """
    Create histograms for data rate distribution for each data type.
    """
    data_types_with_data = [dt for dt, metrics in metrics_by_type.items() if metrics]
    if not data_types_with_data:
        print("No data available for data rate distribution")
        return
    
    fig, axes = plt.subplots(len(data_types_with_data), 1, figsize=(10, 4*len(data_types_with_data)), sharex=True)
    if len(data_types_with_data) == 1:
        axes = [axes]
    
    for i, data_type in enumerate(data_types_with_data):
        aggregated = aggregate_metrics(metrics_by_type[data_type])
        if aggregated and aggregated["data_rates"]:
            axes[i].hist(aggregated["data_rates"], bins=20, alpha=0.7)
            axes[i].set_title(f'{data_type.upper()} Data Rate Distribution')
            axes[i].set_ylabel('Frequency')
            axes[i].axvline(aggregated["stats"]["rate"]["mean"], color='r', 
                           linestyle='dashed', linewidth=1,
                           label=f'Mean = {aggregated["stats"]["rate"]["mean"]:.2f} bits/s')
            axes[i].legend()
            axes[i].grid(True, alpha=0.3)
    
    axes[-1].set_xlabel('Data Rate (bits/second)')
    plt.tight_layout()
    
    # Save the figure
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/data_rate_distribution_{timestamp}.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"Data rate distribution chart saved to {output_file}")
    plt.close()

def plot_all_metrics(metrics_by_type, output_dir="."):
    """Plot all available metrics visualizations."""
    plot_bandwidth_comparison(metrics_by_type, output_dir)
    plot_transmission_time_comparison(metrics_by_type, output_dir)
    plot_connections_per_bit(metrics_by_type, output_dir)
    plot_data_rate_distribution(metrics_by_type, output_dir)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="TLS Covert Channel Metrics Visualizer")
    parser.add_argument("--output-dir", type=str, default=".",
                        help="Directory where to save the visualization files (default: current directory)")
    parser.add_argument("--metric", type=str, 
                        choices=["bandwidth", "time", "connections", "distribution", "all"],
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
    
    # Check if we have any data
    if not any(metrics_by_type.values()):
        print("No metrics files found in current directory")
        return
    
    # Print summary of available data
    for data_type, metrics_list in metrics_by_type.items():
        if metrics_list:
            print(f"Found {len(metrics_list)} metrics files for {data_type}")
    
    # Plot requested metrics
    if args.metric == "all":
        plot_all_metrics(metrics_by_type, args.output_dir)
    elif args.metric == "bandwidth":
        plot_bandwidth_comparison(metrics_by_type, args.output_dir)
    elif args.metric == "time":
        plot_transmission_time_comparison(metrics_by_type, args.output_dir)
    elif args.metric == "connections":
        plot_connections_per_bit(metrics_by_type, args.output_dir)
    elif args.metric == "distribution":
        plot_data_rate_distribution(metrics_by_type, args.output_dir)
        
    print(f"Analysis complete. Plots saved to {args.output_dir}")

if __name__ == "__main__":
    main()
