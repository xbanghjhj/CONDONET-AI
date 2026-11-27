import os
import signal
import socket
import subprocess
import sys
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from secrets import token_urlsafe
from time import monotonic, sleep

import httpx

from lab.policy import require


def wait_for(check, timeout, failure):
    deadline = monotonic() + timeout
    while True:
        if result := check():
            return result
        remaining = deadline - monotonic()
        require(remaining > 0, failure)
        sleep(min(0.4, remaining))


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class EvaluationRuntime:
    def __init__(self, lab, output, ui_port=None):
        self.lab = lab
        self.output = output
        self.ui_port = ui_port or free_port()
        self.api_port = free_port()
        self.incidents = output / "incidents.sqlite"
        self.approvals = output / "approvals.sqlite"
        self.action_socket = output / "action.sock"
        self.probe_socket = output / "probe.sock"
        self.token = token_urlsafe()
        self.stack = ExitStack()
        self.client = httpx.Client(base_url=f"http://127.0.0.1:{self.api_port}", trust_env=False,
                                   headers={"Authorization": f"Bearer {self.token}"}, timeout=650)

    @property
    def ui_url(self):
        return f"http://127.0.0.1:{self.ui_port}"

    @staticmethod
    def stop(process):
        if process.poll() is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=145)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()

    @contextmanager
    def serve(self, name, argv, ready, env=None):
        with (self.output / f"{name}.log").open("a", encoding="utf-8") as log:
            process = subprocess.Popen(argv, stdout=log, stderr=log, start_new_session=True, env=env)
        def healthy():
            require(process.poll() is None, f"{name} exited, see {self.output / f'{name}.log'}")
            try:
                return ready()
            except httpx.TransportError:
                return False
        try:
            wait_for(healthy, 25, f"{name} did not start")
            yield
        finally:
            self.stop(process)

    def api(self):
        command = ("setpriv", "--no-new-privs", sys.executable, "-m", "app.api",
                   "--lab", self.lab, "--operator", "vm-operator", "--approval-db", str(self.approvals),
                   "--action-socket", str(self.action_socket), "--incident-db", str(self.incidents),
                   "--probe-socket", str(self.probe_socket), "--port", str(self.api_port))
        if os.access("/var/run/docker.sock", os.W_OK):
            command = ("bwrap", "--bind", "/", "/", "--tmpfs", "/run", "--", *command)
        return self.serve("api", command, lambda: self.query("GET", "/health")["lab"] == self.lab,
                          {**os.environ, "CONDONET_OPERATOR_TOKEN": self.token})

    def __enter__(self):
        self.stack.enter_context(self.client)
        try:
            self.stack.enter_context(self.serve("probe", (
                sys.executable, "-m", "runner.probe_socket", "--lab", self.lab,
                "--socket", str(self.probe_socket)), self.probe_socket.is_socket))
            self.stack.enter_context(self.serve("action", (
                sys.executable, "-m", "runner.action_socket", "--lab", self.lab, "--db", str(self.approvals),
                "--socket", str(self.action_socket), "--api-uid", str(os.getuid())), self.action_socket.is_socket))
            self.stack.enter_context(self.api())
            self.stack.enter_context(self.serve("ui", (
                sys.executable, "-m", "streamlit", "run", "ui/app.py", "--server.address", "127.0.0.1",
                "--server.port", str(self.ui_port), "--server.fileWatcherType", "none",
                "--server.headless", "true", "--browser.gatherUsageStats", "false"),
                lambda: httpx.get(f"{self.ui_url}/_stcore/health", trust_env=False).is_success,
                {**os.environ, "CONDONET_OPERATOR_TOKEN": self.token, "CONDONET_API_PORT": str(self.api_port),
                 "PYTHONPATH": str(Path.cwd())}))
        except BaseException:
            self.stack.close()
            raise
        return self

    def query(self, method, path):
        response = self.client.request(method, path, **({"timeout": 10} if method == "GET" else {}))
        response.raise_for_status()
        return response.json()

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.stack.close()
