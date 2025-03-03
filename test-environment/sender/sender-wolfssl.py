import socket
import wolfssl
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Global Configuration
SERVER_IP = "192.168.0.20"
PERMUTATIONS_FILE = "permutations_scenario1.json"
PERMUTATIONS = {}

# Mapping of cipher suites to symbolic representation
CIPHER_MAPPING = {
    "c1": "TLS13-AES128-GCM-SHA256",
    "c2": "TLS13-AES256-GCM-SHA384",
    "c3": "TLS13-CHACHA20-POLY1305-SHA256",
    "c4": "TLS13-AES128-CCM-SHA256",
    "c5": "TLS13-AES128-CCM-8-SHA256"
}

def load_permutations():
    """Loads the permutations JSON file into a global dictionary."""
    global PERMUTATIONS

    if not os.path.exists(PERMUTATIONS_FILE):
        print(f"Error: {PERMUTATIONS_FILE} not found.")
        return

    with open(PERMUTATIONS_FILE, "r") as file:
        data = json.load(file)

    if not isinstance(data, list):
        print("Error: JSON format is incorrect. Expected a list.")
        return

    for entry in data:
        if "ASCII" in entry and "Permutation" in entry:
            ascii_key = str(entry["ASCII"])
            permutation_list = [c.strip() for c in entry["Permutation"].split() if c.strip()]

            if len(permutation_list) != 10:
                print(f"Warning: ASCII {ascii_key} has {len(permutation_list)} ciphers instead of 10! Check JSON.")

            PERMUTATIONS[ascii_key] = permutation_list

def get_cipher_lists(ascii_char):
    """Retrieves two cipher suite lists (first 5 and last 5) based on the ASCII character."""
    ascii_value = ord(ascii_char)
    permutation_entry = PERMUTATIONS.get(str(ascii_value))

    if not permutation_entry:
        print(f"No permutation found for ASCII value {ascii_value} ('{ascii_char}').")
        return None, None

    if len(permutation_entry) != 10:
        print(f"ERROR: ASCII {ascii_value} permutation has {len(permutation_entry)} elements, expected 10!")
        return None, None

    first_half = permutation_entry[:5]
    second_half = permutation_entry[5:]

    cipher_list_1 = [CIPHER_MAPPING.get(c, f"UNKNOWN({c})") for c in first_half]
    cipher_list_2 = [CIPHER_MAPPING.get(c, f"UNKNOWN({c})") for c in second_half]

    return ":".join(cipher_list_1), ":".join(cipher_list_2)

def create_tls_connection(ciphers):
    """Establishes a TLS connection using wolfSSL with a specified cipher suite."""
    try:
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_3)
        context.set_ciphers(ciphers)
        tls_connection = context.wrap_socket(bind_socket)
        tls_connection.connect((SERVER_IP, 443))
        print(f"TLS connection established to {SERVER_IP}")
        return tls_connection
    except Exception as e:
        print(f"Error establishing TLS connection: {e}")
        return None

def tls_connection_for_ascii_character(ascii_char):
    """
    Establishes a TLS connection for a given ASCII character using the cipher suite mapping.
    Ensures conn_1 completes before conn_2 starts.
    """
    cipher_string_1, cipher_string_2 = get_cipher_lists(ascii_char)

    if cipher_string_1:
        tls_conn_1 = create_tls_connection(cipher_string_1)
        if tls_conn_1:
            tls_conn_1.close()
        else:
            print(f"Failed to establish first TLS connection for '{ascii_char}', skipping second.")

    if cipher_string_2:
        tls_conn_2 = create_tls_connection(cipher_string_2)
        if tls_conn_2:
            tls_conn_2.close()

def send_key_over_tls(ascii_key):
    """
    Iterates through the key's ASCII characters and transmits them using the covert channel.
    Ensures sequential execution.
    """
    # Debugging
    print(f"Encoding key: {ascii_key[:50]}...")

    for char in ascii_key:
        tls_connection_for_ascii_character(char)

def generate_keys(n, key_type):
    """Generates `n` RSA-4096 or ECC-256 private keys and sends them over TLS."""

    def save_key_to_file(key_data, key_type, num):
        """Saves the key to a persistent file."""
        folder = "/tmp"
        filename = f"{folder}/{key_type}_key_{num}.pem"
        with open(filename, "wb") as key_file:
            key_file.write(key_data)
        return filename

    def convert_to_ascii(key_data):
        """Attempts to convert binary key data to an ASCII string."""
        try:
            return key_data.decode("ascii")
        except UnicodeDecodeError:
            print("Warning: Non-ASCII characters detected.")

    for i in range(1, n + 1):
        if key_type == "rsa":
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        elif key_type == "ecc":
            key = ec.generate_private_key(ec.SECP256R1())
        else:
            print("Invalid key type. Use 'rsa' or 'ecc'.")
            return

        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        save_key_to_file(key_pem, key_type, i)

        ascii_key = convert_to_ascii(key_pem)
        if ascii_key:
            send_key_over_tls(ascii_key)

    print(f"{n} {key_type.upper()} keys successfully generated and transmitted.")

def main():
    """Main function to handle interactive user input commands."""
    print("Waiting for commands...")
    
    load_permutations()

    while True:
        command = input("Enter command (e.g., test rsa 50, connect A, exit): ").strip()

        if command.lower() == "exit":
            print("Exiting the program...")
            break

        elif command.startswith("test"):
            parts = command.split()
            if len(parts) == 3 and parts[1] in ["rsa", "ecc"] and parts[2].isdigit():
                key_type = parts[1]
                num_keys = int(parts[2])
                generate_keys(num_keys, key_type)
            else:
                print("Invalid command. Example: test rsa 50 or test ecc 50")

        elif command.startswith("connect"):
            try:
                _, ascii_input = command.split()
                ascii_value = ord(ascii_input)

                if not (0 <= ascii_value <= 255):
                    print("Error: ASCII value must be between 0-255.")
                    continue

                ascii_char = chr(ascii_value)
                tls_connection_for_ascii_character(ascii_char)
            except ValueError:
                print("Invalid command. Example: connect A or connect 0")

        else:
            print("Unknown command! Use 'test <ENC> <N>' or 'connect <ASCII>' or 'exit'.")

if __name__ == "__main__":
    main()