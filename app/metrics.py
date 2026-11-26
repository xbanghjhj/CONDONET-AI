import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from time import time

METRICS_ADDRESS = ("127.0.0.1", 9108)
MEASUREMENTS = (
    "dns_success", "dns_latency_seconds", "http_status", "http_body_match",
    "http_latency_seconds", "rtt_seconds", "packet_loss_ratio",
)


def render_metrics(samples, stale_after, now):
    metrics = {name: [] for name in (
        "probe_state", "probe_sample_present", "probe_sample_timestamp_seconds",
        "availability", *MEASUREMENTS,
    )}
    for probe, sample in samples:
        labels = ",".join(f"{key}={json.dumps(value)}" for key, value in
                          zip(("source_node", "service", "probe"), probe.labels))
        state = "missing"
        if sample is not None:
            observed_at = sample.timestamp.timestamp()
            metrics["probe_sample_timestamp_seconds"].append((labels, observed_at))
            state = sample.status if 0 <= now - observed_at <= stale_after else "stale"

        present = state not in {"missing", "stale"}
        metrics["probe_state"].append((f'{labels},state="{state}"', 1))
        metrics["probe_sample_present"].append((labels, int(present)))
        if state in {"healthy", "failed"}:
            metrics["availability"].append((labels, int(state == "healthy")))
            for name in MEASUREMENTS:
                if name in sample.measurements:
                    metrics[name].append((labels, sample.measurements[name]))

    lines = []
    for name, rows in metrics.items():
        if rows:
            metric = f"condonet_{name}"
            lines.append(f"# TYPE {metric} gauge")
            lines.extend(f"{metric}{{{labels}}} {value}" for labels, value in rows)
    return "\n".join(lines) + "\n"


class MetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_error(404)
            return
        body = render_metrics(self.server.collector.snapshot(), self.server.stale_after,
                              time()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MetricsServer(ThreadingHTTPServer):
    def __init__(self, collector, stale_after):
        self.collector = collector
        self.stale_after = stale_after
        super().__init__(METRICS_ADDRESS, MetricsHandler)
