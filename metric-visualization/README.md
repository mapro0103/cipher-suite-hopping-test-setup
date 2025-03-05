# TLS Covert Channel Metrics Visualizer

This tool visualizes and analyzes metrics collected from TLS covert channel transmissions. It creates comparative visualizations between different data types (password, RSA, ECC) to evaluate performance and efficiency.

## Overview

The metrics visualizer reads JSON metric files exported by the TLS covert channel monitor and generates various plots to help analyze:

- Bandwidth comparison between different data types
- Transmission time distribution
- Connection efficiency (connections per bit)
- Data rate distribution

## Requirements

- Python 3.6+
- Required packages:
  - numpy
  - matplotlib
  - datetime
  - argparse

Install requirements:

```bash
pip install numpy matplotlib
```

## Usage

1. **Copy metrics files to the script directory**:
   - Place your `metrics_*.json` files in the same directory as the script

2. **Run the script**:
   ```bash
   python metrics_visualizer.py
   ```

3. **View the generated plots**:
   - Plots are saved to the current directory by default
   - Each plot includes a timestamp in the filename to avoid overwriting

## Command Line Options

```
usage: metrics_visualizer.py [-h] [--output-dir OUTPUT_DIR]
                            [--metric {bandwidth,time,connections,distribution,all}]

optional arguments:
  -h, --help            show this help message and exit
  --output-dir OUTPUT_DIR
                        Directory where to save the visualization files
                        (default: current directory)
  --metric {bandwidth,time,connections,distribution,all}
                        Specific metric to visualize (default: all)
```

### Examples

Generate all visualizations:
```bash
python metrics_visualizer.py
```

Generate only bandwidth comparison:
```bash
python metrics_visualizer.py --metric bandwidth
```

Save plots to a specific directory:
```bash
python metrics_visualizer.py --output-dir ./plots
```

## Available Visualizations

1. **Bandwidth Comparison**: Bar chart showing average bandwidth for each data type with standard deviation error bars.

2. **Transmission Time Comparison**: Box plot showing the distribution of transmission times for each data type.

3. **Connections per Bit**: Bar chart showing the efficiency of data transmission in terms of TLS connections needed per bit.

4. **Data Rate Distribution**: Histograms showing the distribution of data rates for each data type.

## Metrics File Format

The tool expects metrics files in the following JSON format:

```json
{
  "timestamp": "2025-03-04 12:34:56",
  "data_type": "password",
  "num_transmissions": 5,
  "total_bits": 1600,
  "total_bytes": 200,
  "total_transmission_time": 10.5,
  "total_connections": 100,
  "avg_bandwidth_bits": 152.38,
  "avg_bandwidth_bytes": 19.05,
  "transmission_times": [2.1, 2.3, 1.9, 2.0, 2.2],
  "transmission_sizes": [320, 320, 320, 320, 320],
  "data_rates": [152.38, 139.13, 168.42, 160.0, 145.45],
  "connections_per_transmission": [20, 20, 20, 20, 20],
  "stats": {
    "time": { "mean": 2.1, "std": 0.15, "min": 1.9, "max": 2.3 },
    "size": { "mean": 320, "std": 0, "min": 320, "max": 320 },
    "rate": { "mean": 153.08, "std": 11.56, "min": 139.13, "max": 168.42 },
    "connections": { "mean": 20, "std": 0, "min": 20, "max": 20 }
  }
}
```
