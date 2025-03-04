# TLS Cipher-Suite-Hopping Covert Channel

This repository contains a Python implementation of a covert channel using TLS handshakes and cipher suite permutations. The script can encode and transmit sensitive data like passwords, RSA keys, or ECC keys through a series of TLS connections by encoding data in the sequence of cipher suites used during the TLS handshake.

## How It Works

The covert channel operates on the principle that the sequence of cipher suites offered during TLS handshakes can be used to encode information:

1. Each ASCII character in the source data (password or cryptographic key) is mapped to a specific permutation of TLS 1.3 cipher suites.
2. For each character, two TLS connections are established sequentially, each using a different subset of cipher suites.
3. The receiver (not included in this repository) can decode the information by observing the cipher suites offered in each connection.

## Prerequisites

- Python 3.6+
- Required Python packages:
  - `socket`
  - `wolfssl`
  - `json`
  - `cryptography`
- A JSON file named `permutations.json` in the same directory as the script
- A server running at the IP address specified in the script (default: 192.168.0.20)

## Usage

The script supports the following command-line arguments:

```bash
# Generate and transmit 5 random passwords
python sender-wolfssl-updated.py --data password --n 5

# Generate and transmit 10 RSA-4096 keys
python sender-wolfssl-updated.py --data rsa --n 10

# Generate and transmit 3 ECC-SECP256R1 keys
python sender-wolfssl-updated.py --data ecc --n 3

# Generate and transmit all three types (5 of each by default)
python sender-wolfssl-updated.py --all

# Generate and transmit all three types (10 of each)
python sender-wolfssl-updated.py --all --n 10
```

## Output

The script generates two types of output:

1. **Console output**: Progress and status messages during the generation and transmission process.
2. **Text files**: The generated data (passwords or keys) are saved to timestamped text files:
   - `password_YYYYMMDD_HHMMSS.txt`
   - `rsa_YYYYMMDD_HHMMSS.txt`
   - `ecc_YYYYMMDD_HHMMSS.txt`

## Cipher Suite Mapping

The script uses the following TLS 1.3 cipher suites:

- `c1`: TLS13-AES128-GCM-SHA256
- `c2`: TLS13-AES256-GCM-SHA384
- `c3`: TLS13-CHACHA20-POLY1305-SHA256
- `c4`: TLS13-AES128-CCM-SHA256
- `c5`: TLS13-AES128-CCM-8-SHA256

Each ASCII character is mapped to two groups of cipher suites, which are specified in the `permutations_scenario1.json` file.

## Permutations File Format

The `permutations.json` file should contain a mapping of ASCII values to cipher suite permutations. The expected format is:

```json
[
  {
    "ASCII": [65, 97],
    "Permutation": [["c1", "c2", "c3", "c4", "c5"], ["c3", "c1", "c5", "c2", "c4"]]
  },
  {
    "ASCII": [66, 98],
    "Permutation": [["c2", "c1", "c3", "c5", "c4"], ["c4", "c3", "c2", "c1", "c5"]]
  }
  ...
]
```

In this example:
- Both uppercase 'A' (ASCII 65) and lowercase 'a' (ASCII 97) are mapped to the same permutation
- Each permutation contains two lists, corresponding to the two TLS connections used to transmit two character

## Security Considerations

This covert channel implementation is designed to evade detection by network monitoring tools that don't specifically look for patterns in TLS cipher suite offerings. However:

1. The channel has a relatively low bandwidth, as two characters requires two full TLS handshakes.
2. Repeated connections with unusual cipher suite preferences might trigger alerts in sophisticated network monitoring systems.
3. The server must support all the TLS 1.3 cipher suites used in the permutations.

## Files

- `sender-wolfssl.py`: Original implementation with interactive command interface
- `permutations.json`: Configuration file for character-to-cipher-suite mappings

## Note

This tool is provided for educational and research purposes only. Use of covert channels may violate security policies or regulations in certain environments.


# ToDo

1. Create certificate for TLS: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 1000 -nodes

