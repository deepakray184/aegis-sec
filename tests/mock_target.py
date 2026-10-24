"""
Mock target server for verifying end-to-end security audit and report generation.
"""

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import time

class VulnerableTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Deliberately insecure response for testing audit detection
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/7.4.3")
        self.send_header("Set-Cookie", "auth_session=secret_token_12345; Path=/")  # Missing Secure, HttpOnly, SameSite
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Corporate Web Portal</h1><p>Welcome to Internal Test App</p></body></html>")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE")
        self.end_headers()

    def do_TRACE(self):
        self.send_response(200)
        self.send_header("Content-Type", "message/http")
        self.end_headers()
        self.wfile.write(b"TRACE / HTTP/1.1\r\n")

    def log_message(self, format, *args):
        pass

def run_test_server(port=9999):
    server = ThreadingHTTPServer(("127.0.0.1", port), VulnerableTargetHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server

if __name__ == "__main__":
    server = run_test_server(9999)
    print("Mock server running on http://127.0.0.1:9999")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.shutdown()
