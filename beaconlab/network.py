"""Local synthetic endpoint and a transparent TCP stream observer.

The observer records actual socket traffic, not fabricated packets. It is an
active forwarding measurement point, not a passive packet capture. Byte counts
are TCP application payload bytes (including TLS records when present).
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import select
import socket
import socketserver
import ssl
import threading
import time

from .tls import ja3_from_stream


class ExchangeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "BeaconLab"
    sys_version = ""

    def log_message(self, *_args):
        pass

    def do_POST(self):
        if self.path != "/exchange":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 16384:
                self.send_error(413)
                return
            message = json.loads(self.rfile.read(length))
            if not isinstance(message, dict) or set(message) != {"sample", "padding"}:
                self.send_error(400)
                return
            if not isinstance(message["sample"], str) or not isinstance(message["padding"], str):
                self.send_error(400)
                return
        except (ValueError, UnicodeError):
            self.send_error(400)
            return
        # All workloads receive exactly the same harmless acknowledgement.
        # There is no command dispatch, file access, or operating-system action.
        payload = json.dumps({"ok": True, "ack": "synthetic exchange", "padding": "r" * 256}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class Controller:
    def __init__(self, *, certificate=None, private_key=None):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ExchangeHandler)
        self.server.daemon_threads = True
        if certificate:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(certificate, private_key)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def http_user_agent(data: bytes) -> str | None:
    # Never interpret a TLS byte stream as plaintext HTTP.
    if not data.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ")):
        return None
    head, separator, _ = data.partition(b"\r\n\r\n")
    if not separator:
        return None
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.lower() == b"user-agent":
            return value.decode("latin-1").strip()[:512]
    return None


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        observer = self.server.observer
        with observer.lock:
            run_id = observer.active_run
            observer.busy += 1
        started = time.time()
        timer = time.monotonic()
        upstream = None
        orig_bytes = resp_bytes = 0
        prefix = bytearray()
        error = None
        try:
            self.request.settimeout(5)
            upstream = socket.create_connection(("127.0.0.1", observer.target_port), timeout=5)
            readers = [self.request, upstream]
            while readers:
                ready, _, _ = select.select(readers, [], [], 5)
                if not ready:
                    error = "idle_timeout"
                    break
                for source in ready:
                    destination = upstream if source is self.request else self.request
                    chunk = source.recv(65536)
                    if not chunk:
                        readers.remove(source)
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    if source is self.request:
                        orig_bytes += len(chunk)
                        remaining = 131072 - len(prefix)
                        if remaining > 0:
                            prefix.extend(chunk[:remaining])
                    else:
                        resp_bytes += len(chunk)
                    destination.sendall(chunk)
        except OSError as exc:
            error = type(exc).__name__
        finally:
            if upstream is not None:
                upstream.close()
            ended = time.time()
            fingerprint = ja3_from_stream(bytes(prefix)) if observer.transport == "https" else None
            record = {
                "ts": started, "completed_ts": ended,
                "duration": time.monotonic() - timer,
                "orig_bytes": orig_bytes, "resp_bytes": resp_bytes,
                "user_agent": http_user_agent(bytes(prefix)) if observer.transport == "http" else None,
                "ja3": fingerprint["ja3"] if fingerprint else None,
                "ja3_string": fingerprint["ja3_string"] if fingerprint else None,
                "transport": observer.transport, "run_id": run_id,
                "observer": "tcp_stream_proxy", "error": error,
            }
            with observer.lock:
                if run_id is not None:
                    observer.records.append(record)
                observer.busy -= 1


class StreamObserver:
    def __init__(self, target_port: int, transport: str):
        self.target_port, self.transport = target_port, transport
        self.lock = threading.Lock()
        self.records = []
        self.active_run = None
        self.busy = 0
        self.server = _ProxyServer(("127.0.0.1", 0), _ProxyHandler)
        self.server.observer = self
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def begin(self, run_id: str):
        self.wait_idle()
        with self.lock:
            self.records = []
            self.active_run = run_id

    def wait_idle(self, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if not self.busy:
                    return
            time.sleep(0.005)
        raise RuntimeError("Observer did not become idle")

    def end(self):
        self.wait_idle()
        with self.lock:
            result = sorted(self.records, key=lambda row: row["completed_ts"])
            self.active_run = None
            self.records = []
        return result

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
