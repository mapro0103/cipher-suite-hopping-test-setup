from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import threading

class SimpleRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Ensure HTTP/1.1 is used
        self.protocol_version = "HTTP/1.1"

        # Respond with a simple message
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
    https_server_address = ('0.0.0.0', 443)
    httpd = HTTPServer(https_server_address, SimpleRequestHandler)

    # Create SSL context with both TLS 1.2 and TLS 1.3 enabled
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Allow TLS 1.2 as minimum
    context.maximum_version = ssl.TLSVersion.TLSv1_3  # Allow TLS 1.3 as maximum

    # Load the server's certificate and private key
    context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")
 
    # Wrap the HTTP server's socket with the SSL context
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print("HTTPS server is running on port 443...")
    httpd.serve_forever()

if __name__ == "__main__":
    print("I am receiver.py")

    # Start HTTP and HTTPS servers in separate threads
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    https_thread = threading.Thread(target=run_https_server, daemon=True)

    http_thread.start()
    https_thread.start()

    # Keep the main thread alive
    http_thread.join()
    https_thread.join()
