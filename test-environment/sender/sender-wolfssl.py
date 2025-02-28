import socket
import wolfssl
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

def generate_keys(n, key_type, encode_data):
    """Generates `n` RSA-4096 or ECC-256 private keys, saves them, and calls encode_data synchronously."""
    
    def save_key_to_file(key_data, key_type, num):
        """Saves the key to a persistent file inside the container (in /app/sender_keys)."""
        folder = "/tmp"
        filename = f"{folder}/{key_type}_key_{num}.pem"
        with open(filename, "wb") as key_file:
            key_file.write(key_data)
        return filename

    def convert_to_ascii(key_data):
        """Attempts to convert binary key data to an ASCII string, falling back to UTF-8 if needed."""
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

def create_tls_connection(ip_address, ciphers):
    """Establishes a TLS connection using wolfSSL with a specified cipher suite."""
    try:     
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_3)

        # Set the predefined cipher suite list
        context.set_ciphers(ciphers)

        tls_connection = context.wrap_socket(bind_socket)
        tls_connection.connect((ip_address, 443))

        print(f"TLS connection established to {ip_address} with ciphers: {ciphers}")
        return tls_connection
    except Exception as e:
        print(f"Error establishing TLS connection: {e}")
        return None

def main():
    """Main function to handle interactive user input commands."""
    print("Waiting for commands...")

    while True:
        command = input("Enter command (e.g., test rsa 50, connect 192.68.0.20, exit): ").strip().lower()
        
        if command == 'exit':
            print("Exiting the program...")
            break
        
        # Handle key generation command
        if command.startswith("test"):
            parts = command.split()
            if len(parts) == 3 and parts[1] in ["rsa", "ecc"] and parts[2].isdigit():
                key_type = parts[1]
                num_keys = int(parts[2])
                generate_keys(num_keys, key_type, encode_data)
            else:
                print("Invalid command. Example: test rsa 50 or test ecc 50")
        
        # Handle TLS connection command (ciphers are predefined)
        elif command.startswith("connect"):
            try:
                _, ip_address = command.split()
                
                # Define the cipher suite list
                predefined_ciphers = "TLS13-AES128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES256-GCM-SHA384:TLS13-AES128-CCM-SHA256:TLS13-AES128-CCM-8-SHA256"

                # Call create_tls_connection with predefined ciphers
                tls_connection = create_tls_connection(ip_address, predefined_ciphers)
                
                if tls_connection:
                    print(f"Successfully connected to {ip_address} using predefined ciphers.")

                    # # Wait 1 second before terminating
                    # time.sleep(1)
                    
                    print("Terminating connection..")
                    tls_connection.close()
                    print(f"Connection to {ip_address} closed.")
                else:
                    print("Connection could not be established.")
            except ValueError:
                print("Invalid command. Example: connect 192.168.0.20")
        
        else:
            print("Unknown command! Use 'test rsa 50 or test ecc 50', 'connect 192.168.0.20' or 'exit'.")

if __name__ == "__main__":
    main()
