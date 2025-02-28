import socket
import wolfssl
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

# Mapping of cipher suites to symbolic representation
CIPHER_MAPPING = {
    "c1": "TLS13-AES128-GCM-SHA256",
    "c2": "TLS13-AES256-GCM-SHA384",
    "c3": "TLS13-CHACHA20-POLY1305-SHA256",
    "c4": "TLS13-AES128-CCM-SHA256",
    "c5": "TLS13-AES128-CCM-8-SHA256"  
}

def load_permutations():
    """Loads the permutations JSON file and converts it into a dictionary based on ASCII values."""
    json_path = "permutations_5x5.json"
    if not os.path.exists(json_path):
        print(f"Error: {json_path} not found.")
        return None

    with open(json_path, "r") as file:
        data = json.load(file)

    if not isinstance(data, list):
        print("Error: JSON format is incorrect. Expected a list.")
        return None

    # Convert list to dictionary where ASCII value is the key
    permutations_dict = {}
    for entry in data:
        if "ASCII" in entry and "Permutation" in entry:
            ascii_key = str(entry["ASCII"])

            # Ensure the permutation is correctly formatted
            permutation_list = [c.strip() for c in entry["Permutation"].split() if c.strip()]

            # Ensure exactly 10 ciphers are included (5 per TLS connection)
            if len(permutation_list) != 10:
                print(f"Warning: ASCII {ascii_key} has {len(permutation_list)} ciphers instead of 10! Check JSON.")

            permutations_dict[ascii_key] = permutation_list

    return permutations_dict

def get_cipher_lists(ascii_char, permutations):
    """Retrieves two cipher suite lists (first 5 and last 5) based on the ASCII character."""
    ascii_value = ord(ascii_char)
    
    # Look up the permutation for the ASCII value
    permutation_entry = permutations.get(str(ascii_value))
    
    if not permutation_entry:
        print(f"No permutation found for ASCII value {ascii_value} ('{ascii_char}').")
        return None, None

    # Ensure we are actually dealing with a 10-element list
    if len(permutation_entry) != 10:
        print(f"ERROR: ASCII {ascii_value} permutation has {len(permutation_entry)} elements, expected 10!")
        return None, None

    # Split into two groups of 5 ciphers each
    first_half = permutation_entry[:5]
    second_half = permutation_entry[5:]

    # Convert permutation labels to actual cipher names
    cipher_list_1 = [CIPHER_MAPPING.get(c, f"UNKNOWN({c})") for c in first_half]
    cipher_list_2 = [CIPHER_MAPPING.get(c, f"UNKNOWN({c})") for c in second_half]

    return ":".join(cipher_list_1), ":".join(cipher_list_2)  # Format required for wolfSSL

def create_tls_connection(ip_address, ciphers):
    """Establishes a TLS connection using wolfSSL with a specified cipher suite."""
    try:
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_3)
        context.set_ciphers(ciphers)
        tls_connection = context.wrap_socket(bind_socket)
        tls_connection.connect((ip_address, 443))
        print(f"TLS connection established to {ip_address}")
        return tls_connection
    except Exception as e:
        print(f"Error establishing TLS connection: {e}")
        return None

def generate_keys(n, key_type, encode_data):
    """Generates `n` RSA-4096 or ECC-256 private keys, saves them, and calls encode_data synchronously."""
    
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
            # Generate RSA-4096 key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
        elif key_type == "ecc":
            # Generate ECC-256 key
            key = ec.generate_private_key(ec.SECP256R1())
        else:
            print("Invalid key type. Use 'rsa' or 'ecc'.")
            return

        # Convert the key to PEM format
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Save the key and call encode_data synchronously
        save_key_to_file(key_pem, key_type, i)
        encode_data(convert_to_ascii(key_pem))  # Ensuring this runs before the next key

    print(f"{n} {key_type.upper()} keys successfully generated and saved.")

# Placeholder for encode_data function
def encode_data(ascii_key):
    """Encode data function placeholder."""
    print(f"Encoding key: {ascii_key[:50]}...")  # Placeholder for actual logic

def main():
    """Main function to handle interactive user input commands."""
    print("Waiting for commands...")

    permutations = load_permutations()
    if permutations is None:
        print("Error: Could not load permutations. Exiting...")
        return

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
                generate_keys(num_keys, key_type, encode_data)
            else:
                print("Invalid command. Example: test rsa 50 or test ecc 50")

        elif command.startswith("connect"):
            try:
                _, ascii_input = command.split()
                ip_address = "192.168.0.20"

                # Always convert input to an ASCII value
                ascii_value = ord(ascii_input)

                if not (0 <= ascii_value <= 255):  # Ensure valid ASCII range
                    print("Error: ASCII value must be between 0-255.")
                    continue

                ascii_char = chr(ascii_value)  # Convert ASCII value back to character for lookup

                # Debugging output
                print(f"Using input '{ascii_input}' → Converted to ASCII {ascii_value} → Character: '{ascii_char}'")

                # Retrieve two cipher suite lists (first 5 and last 5)
                cipher_string_1, cipher_string_2 = get_cipher_lists(ascii_char, permutations)

                if cipher_string_1 and cipher_string_2:
                    create_tls_connection(ip_address, cipher_string_1)
                    create_tls_connection(ip_address, cipher_string_2)
                else:
                    print("No valid cipher mapping found.")
            except ValueError:
                print("Invalid command. Example: connect A or connect 0")


        else:
            print("Unknown command! Use 'test <ENC> <N>' or 'connect <ASCII>' or 'exit'.")

if __name__ == "__main__":
    main()
