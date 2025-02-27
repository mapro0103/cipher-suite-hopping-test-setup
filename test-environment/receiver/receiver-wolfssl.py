from http.server import HTTPServer, BaseHTTPRequestHandler
import wolfssl
import threading
import os
import sys
import socket

class SimpleRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.protocol_version = "HTTP/1.1"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        response_message = f"Receiver is running with {self.protocol_version}!".encode()
        self.wfile.write(response_message)

def run_http_server():
    print("Starting HTTP server...")
    http_server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(http_server_address, SimpleRequestHandler)
    print("HTTP server is running on port 80...")
    httpd.serve_forever()

def run_https_server():
    print("Starting HTTPS server...")
    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    bind_socket.bind(("", 443))
    print("HTTPS server is running on port 443...")
    bind_socket.listen(5)

    cert_path = "cert.pem"
    key_path = "key.pem"

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"ERROR: Certificate or key file not found: {cert_path} or {key_path}")
        return

    try:
        context = wolfssl.SSLContext(wolfssl.PROTOCOL_TLSv1_3, server_side=True)
        context.load_cert_chain(cert_path, key_path)
        print("TLS context created and certificates loaded successfully.")
    except Exception as e:
        print(f"ERROR: Failed to initialize TLS context: {e}")
        return

    while True:
        try:
            secure_socket = None
            new_socket, from_addr = bind_socket.accept()
            secure_socket = context.wrap_socket(new_socket)
            print("Connection received from", from_addr)
            
            # # Terminate connection after 1 sec
            # time.sleep(1)
            # secure_socket.close()
            # print(f"Connection to {from_addr} terminated after 1s.")
        except KeyboardInterrupt:
            print("Shutting down HTTPS server...")
            break
        finally:
            if secure_socket:
                secure_socket.close()

    bind_socket.close()

if __name__ == "__main__":
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    https_thread = threading.Thread(target=run_https_server, daemon=True)

    http_thread.start()
    https_thread.start()

    try:
        http_thread.join()
        https_thread.join()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        sys.exit(0)
