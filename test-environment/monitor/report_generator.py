import json
import datetime
import os
import numpy as np

def export_metrics(data_type, metrics):
    """Export metrics to a JSON file for later analysis."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    metrics_file = f"/tmp/metrics_{data_type}_{timestamp}.json"
    
    try:
        with open(metrics_file, "w") as f:
            json.dump(metrics, f, indent=2)
        print(f"Metrics for {data_type} saved to {metrics_file}")
    except Exception as e:
        print(f"Error exporting metrics for {data_type}: {e}")
    
    return metrics_file

def generate_report(data_type, data_collections, packet_start_times,
                   packet_types, packet_lengths, captured_sequences, show_details=False):
    """
    Generates a text report for a specific data type, containing all captured packets,
    their timestamps, cipher suites, and decoded ASCII message.
    """
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
            total_overt_bits = 0  # Add overt bits tracking
            
            # For statistical analysis
            data_rates = []
            transmission_times = []
            transmission_sizes = []
            connections_per_transmission = []
            overt_message_sizes = []  # Add overt message size tracking
            
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
                end_time = packet_start_times[last_packet_idx]
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
                
                # Calculate overt message size for this transmission
                overt_bits = 0
                for idx1, idx2 in packets:
                    overt_bits += packet_lengths[idx1] * 8  # Convert bytes to bits
                    overt_bits += packet_lengths[idx2] * 8
                
                total_overt_bits += overt_bits
                overt_message_sizes.append(overt_bits)
            
            # Calculate statistical values
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
            
            # For overt message sizes
            mean_overt_size = np.mean(overt_message_sizes) if overt_message_sizes else 0
            std_overt_size = np.std(overt_message_sizes) if overt_message_sizes else 0
            min_overt_size = np.min(overt_message_sizes) if overt_message_sizes else 0
            max_overt_size = np.max(overt_message_sizes) if overt_message_sizes else 0
            
            # Write the aggregate statistics at the top
            total_bytes = total_bits / 8
            total_overt_bytes = total_overt_bits / 8
            report.write("Aggregated Statistics:\n")
            report.write(f"Total ASCII Data Transferred: {total_bits} bits ({total_bytes:.2f} bytes)\n")
            report.write(f"Total Character Pairs: {total_pairs} ({total_chars} characters)\n")
            report.write(f"Total Transmission Time: {total_transmission_time:.2f} seconds\n")
            report.write(f"Total TLS Connections: {total_connections}\n")
            report.write(f"Total Overt Message Size: {total_overt_bits} bits ({total_overt_bytes:.2f} bytes)\n")
            
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
            
            # Overt Message Sizes
            report.write("Overt Message Sizes (bits):\n")
            report.write(f"{format_stat('Mean', mean_overt_size)}\n")
            report.write(f"{format_stat('Mean (bytes)', mean_overt_size/8)}\n")
            report.write(f"{format_stat('Std Deviation', std_overt_size)}\n")
            report.write(f"{format_stat('Minimum', min_overt_size)}\n")
            report.write(f"{format_stat('Maximum', max_overt_size)}\n\n")
            
            # Store transmission details for the metrics JSON
            transmission_details = []
            
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
                end_time = packet_start_times[last_packet_idx]
                transmission_time = end_time - start_time
                
                total_chars = len(data) * 2  # Each pair has 2 ASCII chars
                trans_total_bits = total_chars * 8
                trans_total_bytes = trans_total_bits / 8
                
                # Calculate overt message size for this transmission
                overt_bits = 0
                for idx1, idx2 in packets:
                    overt_bits += packet_lengths[idx1] * 8  # Convert bytes to bits
                    overt_bits += packet_lengths[idx2] * 8
                
                overt_bytes = overt_bits / 8
                
                bandwidth_bits = trans_total_bits / transmission_time if transmission_time > 0 else 0
                bandwidth_bytes = trans_total_bytes / transmission_time if transmission_time > 0 else 0
                
                report.write(f"Transmission #{trans_idx}:\n")
                report.write(f"  Start Time: {datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
                report.write(f"  End Time: {datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
                report.write(f"  Duration: {transmission_time:.4f} seconds\n")
                report.write(f"  Covert Data: {trans_total_bits} bits ({trans_total_bytes:.2f} bytes)\n")
                report.write(f"  Overt Data: {overt_bits} bits ({overt_bytes:.2f} bytes)\n")
                report.write(f"  Bandwidth: {bandwidth_bits:.2f} bits/second ({bandwidth_bytes:.2f} bytes/second)\n\n")
                
                # Decode and display the message
                covert_message = ""
                for ascii1, ascii2 in data:
                    covert_message += chr(ascii1) + chr(ascii2)
                
                report.write(f"  Decoded Message:\n{covert_message}\n\n")
                
                # Store transmission details for metrics
                transmission_details.append({
                    "id": trans_idx,
                    "start_time": start_time,
                    "end_time": end_time,
                    "duration": transmission_time,
                    "covert_bits": trans_total_bits,
                    "covert_bytes": trans_total_bytes,
                    "overt_bits": overt_bits,
                    "overt_bytes": overt_bytes,
                    "bandwidth_bits": bandwidth_bits,
                    "bandwidth_bytes": bandwidth_bytes,
                    "connections": len(packets),
                    "covert_message": covert_message
                })
                
                # Detailed packet information only if --details flag is set
                if show_details:
                    report.write("  Captured Packets:\n")
                    
                    for pair_idx, (idx1, idx2) in enumerate(packets, 1):
                        ascii1, ascii2 = data[pair_idx - 1]
                        report.write(f"    Packet Pair {pair_idx}:\n")
                        report.write(f"      Cipher Sequence 1: {', '.join(captured_sequences[idx1])}\n")
                        report.write(f"      Cipher Sequence 2: {', '.join(captured_sequences[idx2])}\n")
                        report.write(f"      Packet Type 1: {packet_types[idx1]}\n")
                        report.write(f"      Packet 1 Size: {packet_lengths[idx1]} bytes ({packet_lengths[idx1]*8} bits)\n")
                        report.write(f"      Packet 1 Start Time: {packet_start_times[idx1]:.4f}\n")
                        report.write(f"      Packet Type 2: {packet_types[idx2]}\n")
                        report.write(f"      Packet 2 Size: {packet_lengths[idx2]} bytes ({packet_lengths[idx2]*8} bits)\n")
                        report.write(f"      Packet 2 Start Time: {packet_start_times[idx2]:.4f}\n")
                        report.write(f"      Decoded ASCII Characters: '{chr(ascii1)}' ({ascii1}), '{chr(ascii2)}' ({ascii2})\n")
                        report.write("      -----------------------------\n")
                
                report.write("\n")
            
            # Export metrics for visualization
            metrics = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "data_type": data_type,
                "num_transmissions": num_transmissions,
                "total_bits": total_bits,
                "total_bytes": total_bytes,
                "total_overt_bits": total_overt_bits,
                "total_overt_bytes": total_overt_bytes,
                "total_transmission_time": total_transmission_time,
                "total_connections": total_connections,
                "avg_bandwidth_bits": avg_bandwidth_bits if total_transmission_time > 0 else 0,
                "avg_bandwidth_bytes": avg_bandwidth_bytes if total_transmission_time > 0 else 0,
                "transmission_times": transmission_times,
                "transmission_sizes": transmission_sizes,
                "overt_message_sizes": overt_message_sizes,
                "data_rates": data_rates,
                "connections_per_transmission": connections_per_transmission,
                "transmissions": transmission_details,
                "stats": {
                    "time": {
                        "mean": float(mean_time),
                        "std": float(std_time),
                        "min": float(min_time),
                        "max": float(max_time)
                    },
                    "size": {
                        "mean": float(mean_size),
                        "std": float(std_size),
                        "min": float(min_size),
                        "max": float(max_size)
                    },
                    "rate": {
                        "mean": float(mean_rate),
                        "std": float(std_rate),
                        "min": float(min_rate),
                        "max": float(max_rate)
                    },
                    "connections": {
                        "mean": float(mean_connections),
                        "std": float(std_connections),
                        "min": float(min_connections),
                        "max": float(max_connections)
                    },
                    "overt_size": {
                        "mean": float(mean_overt_size),
                        "std": float(std_overt_size),
                        "min": float(min_overt_size),
                        "max": float(max_overt_size)
                    }
                }
            }
            
            # Export metrics to a file
            export_metrics(data_type, metrics)
        
        print(f"Report for {data_type} data saved to {REPORT_FILE}")
        # Verify the file was created
        if os.path.exists(REPORT_FILE):
            print(f"Report file exists: {REPORT_FILE}")
        else:
            print(f"WARNING: Report file was not created: {REPORT_FILE}")
    except Exception as e:
        print(f"Error creating report for {data_type}: {e}")
