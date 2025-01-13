from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Receiver is running!")

if __name__ == "__main__":
    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, SimpleRequestHandler)
    httpd.serve_forever()
