import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class WanHandler(BaseHTTPRequestHandler):
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
    with HTTPServer(("10.60.254.2", 8080), WanHandler) as server:
        server.serve_forever()
