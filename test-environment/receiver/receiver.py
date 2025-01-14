from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import threading

class SimpleRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Check if the request is secure (HTTPS)
        if isinstance(self.request, ssl.SSLSocket):
            protocol = "HTTPS"
        else:
            protocol = "HTTP"

        # Respond with the detected protocol
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        response_message = f"Receiver is running with {protocol}!".encode()
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

    # Enable SSL/TLS
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile="key.pem",     # Path to private key
        certfile="cert.pem",   # Path to certificate
        server_side=True
    )
    print("HTTPS server is running on port 443...")
    httpd.serve_forever()

if __name__ == "__main__":
    print("Hello, I am the Receiver")

    # Start HTTP and HTTPS servers in separate threads
    http_thread = threading.Thread(target=run_http_server, daemon=True)
    https_thread = threading.Thread(target=run_https_server, daemon=True)

    http_thread.start()
    https_thread.start()

    # Keep the main thread alive
    http_thread.join()
    https_thread.join()
