import argparse
import json
import os
import signal
import socket
from pathlib import Path
from socketserver import StreamRequestHandler, UnixStreamServer

from app.incident_store import Evidence
from runner.read_tools import ReadOnlyRunner

REQUEST_LIMIT = 512
RESPONSE_LIMIT = 16384


class ProbeClient:
    def __init__(self, path, timeout):
        self.path = path
        self.timeout = timeout

    def run(self, probe_id):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(self.timeout)
            connection.connect(str(self.path))
            connection.sendall(json.dumps({"probe_id": probe_id}).encode() + b"\n")
            with connection.makefile("rb") as stream:
                line = stream.readline(RESPONSE_LIMIT + 1)
        if not line.endswith(b"\n") or len(line) > RESPONSE_LIMIT:
            raise ValueError("Invalid probe response frame")
        response = json.loads(line)
        if not isinstance(response, dict) or set(response) != {"result"}:
            raise ValueError("Probe request rejected")
        return Evidence.from_record(response["result"])


class ProbeHandler(StreamRequestHandler):
    timeout = 3

    def handle(self):
        try:
            line = self.rfile.readline(REQUEST_LIMIT + 1)
            if not line.endswith(b"\n") or len(line) > REQUEST_LIMIT:
                raise ValueError("Invalid request frame")
            request = json.loads(line)
            if (not isinstance(request, dict) or set(request) != {"probe_id"}
                    or not isinstance(request["probe_id"], str)):
                raise ValueError("Expected only one probe ID")
            response = {"result": self.server.runner.run(request["probe_id"]).record()}
        except (TimeoutError, ValueError):
            response = {"error": "invalid_probe_request"}
        try:
            self.wfile.write(json.dumps(response).encode() + b"\n")
        except (BrokenPipeError, ConnectionResetError):
            return


class ProbeServer(UnixStreamServer):
    def __init__(self, path, runner):
        self.runner = runner
        mask = os.umask(0o177)
        try:
            super().__init__(str(path), ProbeHandler)
        finally:
            os.umask(mask)


def stop_server(*_):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description="Serve allowlisted host probes over a local Unix socket.")
    parser.add_argument("--lab", required=True)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    path = args.socket.resolve()
    with ProbeServer(path, ReadOnlyRunner(args.lab)) as server:
        signal.signal(signal.SIGTERM, stop_server)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
