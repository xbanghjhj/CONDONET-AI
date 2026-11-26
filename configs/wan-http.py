import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WanHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != "/source":
            self.send_error(404)
            return

        payload = json.dumps({"source": self.client_address[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    with ThreadingHTTPServer(("10.60.254.2", 80), WanHandler) as server:
        server.serve_forever()
