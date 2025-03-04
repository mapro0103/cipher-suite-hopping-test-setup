import socket
import wolfssl
import json
import os
import argparse
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import random
import string

# Global Configuration
SERVER_IP = "192.168.0.20"
PERMUTATIONS_FILE = "permutations.json"
ASCII_PAIRS = {}

# Mapping of cipher suites to symbolic representation
CIPHER_MAPPING = {
    "c1": "TLS13-AES128-GCM-SHA256",
    "c2": "TLS13-AES256-GCM-SHA384",
    "c3": "TLS13-CHACHA20-POLY1305-SHA256",
    "c4": "TLS13-AES128-CCM-SHA256",
    "c5": "TLS13-AES128-CCM-8-SHA256"
}

def load_permutations():
    """Loads the permutations JSON file into global dictionary."""
    global ASCII_PAIRS

    if not os.path.exists(PERMUTATIONS_FILE):
        print(f"Error: {PERMUTATIONS_FILE} not found.")
        return False

    with open(PERMUTATIONS_FILE, "r") as file:
        data = json.load(file)

    if not isinstance(data, list):
        print("Error: JSON format is incorrect. Expected a list.")
        return False

    # Create the ASCII_PAIRS dictionary
    for entry in data:
        if "ASCII" in entry and "Permutation" in entry and len(entry["ASCII"]) == 2:
            # Create a key from the pair of ASCII values
            ascii_pair_key = f"{entry['ASCII'][0]},{entry['ASCII'][1]}"
            ASCII_PAIRS[ascii_pair_key] = entry["Permutation"]
    
    return len(ASCII_PAIRS) > 0

def get_cipher_lists_for_ascii_pair(ascii_char1, ascii_char2):
    """Retrieves two cipher suite lists based on a pair of ASCII characters."""
    ascii_value1 = ord(ascii_char1)
    ascii_value2 = ord(ascii_char2)
    
    # Create the pair key
    pair_key = f"{ascii_value1},{ascii_value2}"
    
    # Look for an exact match in our ASCII_PAIRS dictionary
    if pair_key in ASCII_PAIRS:
        permutation_entry = ASCII_PAIRS[pair_key]
        
        if len(permutation_entry) != 2:
            print(f"ERROR: ASCII pair {pair_key} permutation doesn't have 2 lists!")
            return None, None
            
        first_half = permutation_entry[0]
        second_half = permutation_entry[1]
        
        cipher_list_1 = [CIPHER_MAPPING.get(c, f"UNKNOWN({c})") for c in first_half]
        cipher_list_2 = [CIPHER_MAPPING.get(c, f"UNKNOWN({c})") for c in second_half]
        
        return ":".join(cipher_list_1), ":".join(cipher_list_2)
    
    print(f"No permutation found for ASCII pair {pair_key}.")
    return None, None

def create_tls_connection(ciphers):
    """Establishes a TLS connection using wolfSSL with a specified cipher suite."""
    try:
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_3)
        context.set_ciphers(ciphers)
        tls_connection = context.wrap_socket(bind_socket)
        tls_connection.connect((SERVER_IP, 443))
        return tls_connection
    except Exception as e:
        print(f"Error establishing TLS connection: {e}")
        return None

def tls_connection_for_ascii_pair(ascii_char1, ascii_char2):
    """
    Establishes a TLS connection for a given pair of ASCII characters using the cipher suite mapping.
    Ensures conn_1 completes before conn_2 starts.
    """
    cipher_string_1, cipher_string_2 = get_cipher_lists_for_ascii_pair(ascii_char1, ascii_char2)

    if cipher_string_1:
        tls_conn_1 = create_tls_connection(cipher_string_1)
        if tls_conn_1:
            tls_conn_1.close()
        else:
            return False

    if cipher_string_2:
        tls_conn_2 = create_tls_connection(cipher_string_2)
        if tls_conn_2:
            tls_conn_2.close()
            return True
        else:
            return False
    
    return False

def send_key_over_tls_pairs(ascii_key):
    """
    Iterates through the key's ASCII characters in pairs and transmits them using the covert channel.
    This method sends two ASCII values in parallel, improving efficiency.
    """
    # Pad the key with a space if it has an odd length
    if len(ascii_key) % 2 != 0:
        ascii_key += " "

    # Process characters in pairs
    for i in range(0, len(ascii_key), 2):
        char1 = ascii_key[i]
        char2 = ascii_key[i+1]
        tls_connection_for_ascii_pair(char1, char2)

def generate_random_password(length=20):
    """
    Generates a secure random password of exactly 20 characters following common password guidelines.
    """
    # Character sets
    uppercase_chars = string.ascii_uppercase
    lowercase_chars = string.ascii_lowercase
    digit_chars = string.digits
    special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Ensure at least one character from each required set
    password = [
        random.choice(uppercase_chars),  # 1 uppercase
        random.choice(lowercase_chars),  # 1 lowercase
        random.choice(digit_chars),      # 1 digit
        random.choice(special_chars)     # 1 special character
    ]
    
    # Fill the remaining length with random characters from all sets
    all_chars = uppercase_chars + lowercase_chars + digit_chars + special_chars
    password.extend(random.choice(all_chars) for _ in range(length - 4))
    
    # Shuffle the password to avoid predictable positions
    random.shuffle(password)
    
    # Make sure the length is even for pair-based transmission
    if length % 2 != 0:
        password.append(random.choice(all_chars))
    
    return ''.join(password)

def save_data_to_file(data_type, data_list):
    """Saves the generated data to a file with timestamp in the /tmp directory."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"/tmp/{data_type}_{timestamp}.txt"
    
    with open(filename, "w") as file:
        for i, data in enumerate(data_list, 1):
            file.write(f"--- {data_type} {i} ---\n")
            file.write(data)
            file.write("\n\n")
    
    print(f"Saved {len(data_list)} {data_type} entries to {filename}")
    return filename

def generate_and_transmit(data_type, count):
    """Generates and transmits the specified data type."""
    data_list = []
    
    if data_type.lower() == "password":
        print(f"Generating and transmitting {count} passwords...")
        for i in range(1, count + 1):
            password = generate_random_password()
            data_list.append(password)
            print(f"Transmitting password {i}/{count}")
            send_key_over_tls_pairs(password)
    
    elif data_type.lower() == "rsa":
        print(f"Generating and transmitting {count} RSA keys...")
        for i in range(1, count + 1):
            key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            ascii_key = key_pem.decode("ascii")
            data_list.append(ascii_key)
            print(f"Transmitting RSA key {i}/{count}")
            send_key_over_tls_pairs(ascii_key)
    
    elif data_type.lower() == "ecc":
        print(f"Generating and transmitting {count} ECC keys...")
        for i in range(1, count + 1):
            key = ec.generate_private_key(ec.SECP256R1())
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            ascii_key = key_pem.decode("ascii")
            data_list.append(ascii_key)
            print(f"Transmitting ECC key {i}/{count}")
            send_key_over_tls_pairs(ascii_key)
    
    else:
        print(f"Invalid data type: {data_type}")
        return None
    
    return save_data_to_file(data_type, data_list)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="TLS Covert Channel Sender")
    
    parser.add_argument("--data", type=str, choices=["password", "rsa", "ecc"],
                        help="Data type to generate and transmit: password, RSA, or ECC")
    parser.add_argument("--all", action="store_true", 
                        help="Generate and transmit all data types sequentially")
    parser.add_argument("--n", type=int, default=5,
                        help="Number of keys/passwords to generate (default: 5)")
    
    args = parser.parse_args()
    
    if not args.data and not args.all:
        parser.error("Either --data or --all must be specified")
    
    return args

def main():
    """Main function to process command line arguments and execute tasks."""
    args = parse_arguments()
    
    # Load cipher permutations
    if not load_permutations():
        print("Failed to load permutations. Exiting.")
        return
    
    if args.all:
        # Process all data types sequentially
        for data_type in ["password", "rsa", "ecc"]:
            generate_and_transmit(data_type, args.n)
    else:
        # Process just the specified data type
        generate_and_transmit(args.data, args.n)

if __name__ == "__main__":
    main()