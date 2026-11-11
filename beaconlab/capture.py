"""Optional real PCAP capture. Never silently substitutes synthetic packets."""
from __future__ import annotations

from pathlib import Path
import shutil
import signal
import subprocess
import time


class PacketCapture:
    def __init__(self, destination: Path, ports: list[int], interface: str):
        binary = shutil.which("tcpdump")
        if not binary:
            raise RuntimeError("tcpdump is unavailable. Omit --pcap for the stream-observer experiment.")
        if not ports or any(not 1 <= port <= 65535 for port in ports):
            raise ValueError("Capture requires explicit lab ports")
        self.destination = destination
        self.log_path = destination.with_suffix(".capture.log")
        self.log = self.log_path.open("w", encoding="utf-8")
        expression = "tcp and host 127.0.0.1 and (" + " or ".join(f"port {p}" for p in ports) + ")"
        self.command = [binary, "-i", interface, "-nn", "-s", "0", "-U", "-w", str(destination), expression]
        try:
            self.process = subprocess.Popen(self.command, stdout=self.log, stderr=self.log)
        except OSError:
            self.log.close()
            raise
        time.sleep(0.25)
        if self.process.poll() is not None:
            self.log.close()
            detail = self.log_path.read_text(encoding="utf-8")[-1200:]
            raise RuntimeError("Packet capture did not start. Check capture permissions: " + detail)

    def close(self):
        forced = False
        try:
            status = self.process.poll()
            if status is None:
                self.process.send_signal(signal.SIGINT)
                try:
                    status = self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    forced = True
                    self.process.kill()
                    status = self.process.wait(timeout=3)
        finally:
            self.log.close()
        # A classic PCAP header alone is 24 bytes. Do not claim successful
        # capture when tcpdump failed or never wrote a packet.
        has_packets = self.destination.exists() and self.destination.stat().st_size > 24
        if forced or status != 0 or not has_packets:
            detail = self.log_path.read_text(encoding="utf-8")[-1200:]
            raise RuntimeError("Packet capture did not finish with usable evidence: " + detail)
