import socket
import wolfssl

def create_tls_connection(ip_address):
    try:     
        
        bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_3)

        # Set Cipher-Suite list
        ciphers = "TLS13-AES128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES256-GCM-SHA384:TLS13-AES128-CCM-SHA256:TLS13-AES128-CCM-8-SHA256"
        context.set_ciphers(ciphers)

        tls_connection = context.wrap_socket(bind_socket)
        tls_connection.connect((ip_address, 443))

        print(f"TLS connection established to {ip_address}!")
        return tls_connection
    except Exception as e:
        print(f"Error establishing TLS connection: {e}")
        return None

def main():
    print("Waiting for commands...")
    
    # Infinite loop waiting for user input
    while True:
        # Input prompt
        command = input("Enter the command (Example: connect 192.168.0.20): ")
        
        if command.lower() == 'exit':
            print("Exiting the program...")
            break
        
        # Validate the input (it should start with 'connect' and include IP)
        if command.startswith("connect"):
            try:
                _, ip_address = command.split()
                tls_connection = create_tls_connection(ip_address)
                if tls_connection:
                    print(f"Successfully connected to {ip_address}!")
                else:
                    print("Connection could not be established.")
            except ValueError:
                print("Invalid command. Example: connect 192.168.0.20")
        else:
            print("Unknown command! Use 'connect <IP-Address>' or 'exit'.")

if __name__ == "__main__":
    main()