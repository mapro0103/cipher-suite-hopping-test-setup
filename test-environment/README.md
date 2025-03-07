# Test Environment

This project implements a covert channel using TLS cipher suite permutations to encode and transmit data. The system consists of a sender, receiver and monitor that work together to establish a hidden communication channel within normal TLS handshakes.

## Overview

The covert channel works by encoding data into specific permutations of TLS cipher suites during the handshake process. By controlling which cipher suites are offered in each ClientHello message, the sender can encode ASCII characters that can be decoded by an observer monitoring the network traffic.

## Docker Environment Setup

The entire test environment is set up using Docker Compose, creating an isolated network for testing the covert channel. This ensures consistent behavior across different systems and simplifies deployment.

### Docker Components

The environment consists of four containers:

1. **Sender**: Contains the client that initiates TLS connections with encoded data
2. **Receiver**: Runs the TLS server that accepts connections from the sender
3. **Intermediate**: Acts as a network intermediate/router between sender and receiver
4. **Monitor**: Passively observes network traffic to decode the covert channel

### Network Configuration

The Docker environment creates an isolated internal network with the following IP assignments:
- Sender: 192.168.0.10
- Receiver: 192.168.0.20
- Intermediate: 192.168.0.30
- Monitor: 192.168.0.40

### Deployment

To deploy the test environment:

```bash
# Start all containers
docker-compose up -d

# To see logs
docker-compose logs -f

# To stop the environment
docker-compose down
```

**Note:** The receiver and monitor containers are automatically started by Docker Compose. Only the `sender-wolfssl.py` script needs to be controlled manually by the user from within the sender container.

## Components

### Sender (`sender-wolfssl.py`)

The sender is responsible for encoding and transmitting data through the covert channel:

- Encodes ASCII characters into specific TLS cipher suite permutations
- Establishes TLS connections with specific cipher suite selection
- Supports transmission of passwords, RSA keys and ECC keys
- Uses special signaling values to indicate the start/end of transmissions

#### Usage

```bash
# Generate and transmit 5 random passwords
python sender-wolfssl.py --data password --n 5

# Generate and transmit 3 RSA keys
python sender-wolfssl.py --data rsa --n 3

# Generate and transmit 2 ECC keys
python sender-wolfssl.py --data ecc --n 2

# Generate and transmit all data types (5 of each)
python sender-wolfssl.py --all --n 5
```

### Receiver (`receiver-wolfssl.py`)

The receiver acts as a TLS server that accepts connections from the sender:

- Runs an HTTPS server on port 443
- Uses the provided certificate and key for TLS connections
- Accepts and processes TLS handshakes from the sender
- Also runs an HTTP server on port 80 for basic connectivity testing

#### Usage

```bash
# Start the receiver
python receiver-wolfssl.py
```

### Monitor (`monitor.py`)

The monitor passively observes network traffic to decode the covert channel:

- Captures TLS ClientHello packets on port 443
- Extracts cipher suites and maps them to their symbolic representations
- Decodes the covert message by matching cipher suite permutations to ASCII values
- Generates detailed reports of captured transmissions
- Calculates statistics on bandwidth, transmission time and data rates
- Creates detailed reports of all transmissions in `/tmp/tls_report_*` files
- Exports statistical metrics as JSON files to `/tmp/metrics_*` for later analysis

#### Usage

```bash
# Basic monitoring
python monitor.py

# Detailed monitoring with packet information in reports
python monitor.py --details
```

### Supporting Scripts

#### `keygen.sh`

Generates a self-signed TLS certificate and key for the receiver:

```bash
# Generate a new certificate and key
./keygen.sh
```

This script creates:
- `cert.pem`: A self-signed X.509 certificate
- `key.pem`: The corresponding RSA private key

#### `attach.sh`

Connects to a running Docker container for debugging or management:

```bash
# Attach to a specific container
./attach.sh container_name
```

#### `cleanup.sh`

Cleans up data directories used by the sender and monitor:

```bash
# Remove all data files
./cleanup.sh
```

## Setup Instructions

1. Generate TLS certificate and key:
   ```bash
   ./keygen.sh
   ```

2. Start the Docker environment:
   ```bash
   docker-compose up -d
   ```

3. Use the attach script to interact with the sender container:
   ```bash
   ./attach.sh sender
   ```

4. From within the sender container, use sender-wolfssl.py to transmit data:
   ```bash
   python sender-wolfssl.py --data password --n 1
   ```

5. Check the monitor container logs for decoded messages:
   ```bash
   docker-compose logs -f monitor
   ```

6. Access the monitor's generated reports and statistics:
   ```bash
   # View the contents of the reports directory
   docker exec monitor ls -la /tmp
   
   # Copy reports to your local machine
   docker cp monitor:/tmp/tls_report_* ./
   docker cp monitor:/tmp/metrics_* ./
   ```

## Requirements

- Docker and Docker Compose
- Python 3.6 or higher (for local development)
- wolfSSL Python bindings
- Scapy (for the monitor)
- cryptography library
- Standard Python libraries (socket, json, etc.)

## Configuration

- The default server IP is set to `192.168.0.20` in the sender script, which matches the Docker environment configuration
- The permutations file (`permutations.json`) must be present and generated using the permutations generator
- Environment variables are configured in the `.env` file

## Important Legal Disclaimer

**This project is strictly for educational and research purposes only.** 

The implementation and use of covert channels may be illegal in many jurisdictions and could violate:
- Computer fraud and abuse laws
- Unauthorized access regulations
- Corporate and organizational security policies
- Data protection regulations
- Telecommunications laws

Using this system on networks without explicit written permission from network owners is likely illegal and unethical. The authors and contributors accept no responsibility for misuse of this code.

## Security Considerations

This covert channel is designed for educational and research purposes. Keep in mind:

- The channel may be detected by advanced network monitoring tools
- The throughput is limited by the TLS handshake rate
- No encryption is applied to the covert data itself (beyond the encoding)

## Files

- `sender-wolfssl.py`: Transmits covert data using TLS handshakes
- `receiver-wolfssl.py`: Receives TLS connections from the sender
- `monitor.py`: Monitors network traffic to decode covert data
- `keygen.sh`: Generates TLS certificates and keys
- `attach.sh`: Attaches to Docker containers for debugging
- `cleanup.sh`: Removes old data files
- `permutations.json`: Contains the mapping between ASCII values and cipher suite permutations
- `docker-compose.yml`: Defines the Docker environment setup
- `.env`: Contains environment variables for the Docker setup

## Permutations File

The covert channel relies on a `permutations.json` file that maps ASCII values to specific cipher suite permutations. This file should be generated using the permutations generator script.
