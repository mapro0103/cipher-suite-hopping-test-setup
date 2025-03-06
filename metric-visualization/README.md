# TLS Cipher Suite Hopping Covert Channel Metrics Visualizer

A Python tool for analyzing and visualizing performance metrics from the TLS cipher suite hopping covert channel.

## Overview

This tool processes JSON metrics files to visualize and analyze key performance characteristics of TLS covert channels, including:

- Effective bandwidth (bits/second) with statistical distribution analysis
- Covert-to-overt data ratio analysis
- Transmission reliability with bit-level accuracy comparison

The script supports multiple data types (password, RSA, and ECC) and generates comparative visualizations to help understand the efficiency and reliability of different covert channel implementations.

## Features

- **Bandwidth Analysis**: Compare effective bandwidth across different data types with statistical insights
- **Covert-to-Overt Ratio**: Analyze the efficiency of data hiding by comparing covert vs. overt data size
- **Transmission Reliability**: Verify data integrity by comparing original and received messages
- **Consolidated Reporting**: Generate comprehensive reports with key metrics in markdown format

## Requirements

- Python 3.6+
- Required libraries:
  - numpy
  - matplotlib
  - argparse
  - glob
  - json

## Usage

```bash
python metrics_visualizer.py [--output-dir OUTPUT_DIR] [--metric {bandwidth,ratio,reliability,all}]
```

### Arguments

- `--output-dir`: Directory where to save the visualization files (default: `./output`)
- `--metric`: Specific metric to analyze (default: `all`)
  - `bandwidth`: Analyze only bandwidth metrics
  - `ratio`: Analyze only covert-to-overt data ratio
  - `reliability`: Analyze only transmission reliability
  - `all`: Analyze all metrics

### Input Files

The script expects the following files in the current directory:

- `metrics_*.json`: Files containing transmission metrics data
- Data type specific files (for reliability comparison):
  - `password_*.json`
  - `rsa_*.json`
  - `ecc_*.json`

### Output Files

The script generates the following output files:

- `bandwidth_comparison.svg`: Bar chart comparing bandwidth across data types
- `bandwidth_boxplot.svg`: Box plot showing bandwidth statistical distribution
- `covert_overt_ratio.svg`: Bar chart showing the ratio of covert to overt data
- `transmission_reliability.svg`: Bar chart showing reliability metrics
- `transmission_reliability.txt`: Detailed report on transmission reliability
- `consolidated_report.md`: Comprehensive report with all key metrics

## Example

```bash
# Analyze all metrics and save results to custom directory
python metrics_visualizer.py --output-dir ./my_analysis

# Analyze only bandwidth metrics
python metrics_visualizer.py --metric bandwidth
```

## Metrics Format

The script expects metrics files in the following format:

```json
{
  "data_type": "password",
  "num_transmissions": 10,
  "total_bits": 2560,
  "total_bytes": 320,
  "total_transmission_time": 5.2,
  "total_connections": 30,
  "total_overt_bits": 102400,
  "total_overt_bytes": 12800,
  "transmission_times": [0.5, 0.48, 0.52, ...],
  "transmission_sizes": [256, 256, 256, ...],
  "data_rates": [512, 533.33, 492.31, ...],
  "connections_per_transmission": [3, 3, 3, ...],
  "overt_message_sizes": [10240, 10240, 10240, ...],
  "transmissions": [
    {
      "covert_message": "secret_password123"
    },
    ...
  ]
}
```