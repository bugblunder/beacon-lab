"""Capture lifecycle checks with a stub process, not claims of live PCAP testing."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from beaconlab.capture import PacketCapture


class CaptureTests(unittest.TestCase):
    def capture_stub(self, folder, status, size):
        capture = PacketCapture.__new__(PacketCapture)
        capture.destination = folder / "capture.pcap"
        capture.destination.write_bytes(b"\x00" * size)
        capture.log_path = folder / "capture.capture.log"
        capture.log = capture.log_path.open("w")
        capture.process = Mock()
        capture.process.poll.return_value = status
        return capture

    def test_completed_capture_requires_success_and_packet_data(self):
        with tempfile.TemporaryDirectory() as temporary:
            capture = self.capture_stub(Path(temporary), 0, 100)
            capture.close()
            self.assertTrue(capture.log.closed)

    def test_failed_or_empty_capture_is_not_reported_as_evidence(self):
        for status, size in ((1, 100), (0, 24), (0, 0)):
            with self.subTest(status=status, size=size), tempfile.TemporaryDirectory() as temporary:
                capture = self.capture_stub(Path(temporary), status, size)
                with self.assertRaisesRegex(RuntimeError, "usable evidence"):
                    capture.close()
                self.assertTrue(capture.log.closed)


if __name__ == "__main__":
    unittest.main()
