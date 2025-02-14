import socket
import ssl

print(ssl.OPENSSL_VERSION)
print(ssl.PROTOCOL_TLS)

def update_openssl_config(ciphers):
    openssl_conf_path = '/etc/ssl/openssl.cnf'  # Path to OpenSSL config file
    
    try:
        with open(openssl_conf_path, 'r') as f:
            config = f.readlines()
        
        # Check if 'CipherString' is already present
        cipher_string_found = False
        for i, line in enumerate(config):
            if line.strip().startswith('CipherString'):
                config[i] = f"CipherString = {ciphers}\n"
                cipher_string_found = True
                break
        
        # If CipherString is not found, add it
        if not cipher_string_found:
            config.append(f"\n[system_default_sect]\nCipherString = {ciphers}\n")
        
        # Write the updated configuration back to the file
        with open(openssl_conf_path, 'w') as f:
            f.writelines(config)
        
        print(f"Updated {openssl_conf_path} with ciphers: {ciphers}")
    
    except Exception as e:
        print(f"Error updating OpenSSL config: {e}")

def create_tls_connection(tls_version, ip_address):
    try:
        # Mapping the TLS versions
        tls_versions = {
            '1.2': ssl.TLSVersion.TLSv1_2,
            '1.3': ssl.TLSVersion.TLSv1_3
        }

        # If the provided version is not valid, raise an error
        if tls_version not in tls_versions:
            raise ValueError(f"Invalid TLS version: {tls_version}")

        # Create TLS context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Set the minimum and maximum TLS version
        context.minimum_version = tls_versions[tls_version]
        context.maximum_version = tls_versions[tls_version]

        # Modify the cipher suite priority
        if tls_version == '1.2':
            ciphers = 'ECDHE-RSA-AES128-GCM-SHA256'
            print(ciphers)
            context.set_ciphers(ciphers)
        elif  tls_version == '1.3':
            ciphers = 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_AES_128_CCM_SHA256:TLS_AES_128_CCM_8_SHA256'
            print(ciphers)
            update_openssl_config(ciphers)
        else:
            raise ValueError(f"Invalid or unsupported TLS version: {tls_version}")


        # Establish connection to the receiver (port 443 for HTTPS)
        connection = socket.create_connection((ip_address, 443))
        
        # Perform TLS handshake
        tls_connection = context.wrap_socket(connection, server_hostname=ip_address)
        print(f"TLS connection established to {ip_address} with TLSv{tls_version}!")
        return tls_connection
    
    except Exception as e:
        print(f"Error establishing TLS connection: {e}")
        return None

def main():
    print("I am sender.py - Waiting for commands...")

    # Infinite loop waiting for user input
    while True:
        # Input prompt
        command = input("Enter the command (Example: connect 1.2 192.168.0.20): ")
        if command.lower() == 'exit':
            print("Exiting the program...")
            break
        
        # Validate the input (it should start with 'connect' and include TLS version and IP)
        if command.startswith("connect"):
            try:
                _, tls_version, ip_address = command.split()
                tls_connection = create_tls_connection(tls_version, ip_address)
                if tls_connection:
                    print(f"Successfully connected to {ip_address}!")
                else:
                    print("Connection could not be established.")
            except ValueError:
                print("Invalid command. Example: connect 1.2 192.168.0.20")
        else:
            print("Unknown command! Use 'connect 1.2 <IP-Address>' or 'exit'.")

if __name__ == "__main__":
    main()