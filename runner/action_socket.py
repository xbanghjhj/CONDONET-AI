import argparse
import os
import signal
import socket
import struct
from pathlib import Path
from socketserver import StreamRequestHandler, ThreadingMixIn, UnixStreamServer

from app.approvals import ApprovalStore, ClaimRequest
from runner.actions import ActionRunner, LabActions, Verifier
from runner.policy import RunnerPolicy
from runner.probe_socket import stop_server
from runner.read_tools import ReadOnlyRunner


FRAME_LIMIT = 1024


class ActionClient:
    def __init__(self, path):
        self.path = path

    def submit(self, ticket):
        request = ClaimRequest(approval_id=ticket.id, incident_id=ticket.plan.incident_id,
                               plan_hash=ticket.plan_hash, actor=ticket.actor)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(8)
            connection.connect(str(self.path))
            connection.sendall(request.model_dump_json().encode() + b"\n")
            with connection.makefile("rb") as stream:
                reply = stream.readline(FRAME_LIMIT + 1)
        return reply == b'{"status":"running"}\n'


class ActionHandler(StreamRequestHandler):
    timeout = 3

    def handle(self):
        server = self.server
        credentials = self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                              struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credentials)
        ticket = None
        try:
            if uid != server.api_uid:
                raise ValueError("Unexpected peer UID")
            line = self.rfile.readline(FRAME_LIMIT + 1)
            if not line.endswith(b"\n") or len(line) > FRAME_LIMIT:
                raise ValueError("Invalid action request frame")
            request = ClaimRequest.model_validate_json(line)
            ticket = server.store.claim(request, server.policy)
        except (OSError, ValueError):
            response = b'{"status":"denied"}\n'
        else:
            response = b'{"status":"running"}\n'
        try:
            self.wfile.write(response)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if ticket is not None:
                server.run_ticket(ticket)


class ActionServer(ThreadingMixIn, UnixStreamServer):
    def __init__(self, path, store, policy, run_ticket, api_uid, socket_gid=None):
        self.path = path
        self.owns_path = False
        self.store = store
        self.policy = policy
        self.run_ticket = run_ticket
        self.api_uid = api_uid
        mask = os.umask(0o177)
        try:
            super().__init__(str(path), ActionHandler)
        finally:
            os.umask(mask)
        try:
            if socket_gid is not None:
                os.chown(path, -1, socket_gid)
                os.chmod(path, 0o660)
        except OSError:
            self.server_close()
            raise

    def server_bind(self):
        super().server_bind()
        self.owns_path = True

    def server_close(self):
        super().server_close()
        if self.owns_path:
            self.path.unlink(missing_ok=True)
            self.owns_path = False


def main():
    parser = argparse.ArgumentParser(description="Serve approved actions for a running Containerlab lab.")
    parser.add_argument("--lab", required=True)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--socket", required=True, type=Path)
    parser.add_argument("--api-uid", required=True, type=int)
    parser.add_argument("--socket-gid", type=int)
    args = parser.parse_args()
    store = ApprovalStore(args.db)
    policy = RunnerPolicy(args.lab)
    runner = ActionRunner(store, LabActions(policy), Verifier(ReadOnlyRunner(args.lab)))
    with ActionServer(args.socket, store, policy, runner, args.api_uid, args.socket_gid) as server:
        signal.signal(signal.SIGTERM, stop_server)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
