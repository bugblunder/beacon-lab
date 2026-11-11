"""Extract JA3 from an observed TLS ClientHello, without decrypting traffic.

This is a bounded implementation of the original JA3 algorithm, not an
application identity or maliciousness classifier. GREASE values are omitted.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess


def _grease(value: int) -> bool:
    return (value >> 8) == (value & 255) and (value & 15) == 10


def ja3_from_stream(data: bytes) -> dict | None:
    """Return a fingerprint only for a complete, structurally valid ClientHello."""
    if len(data) > 131072:
        return None
    handshake = bytearray()
    cursor = 0
    try:
        while cursor + 5 <= len(data):
            kind = data[cursor]
            size = int.from_bytes(data[cursor + 3:cursor + 5], "big")
            if size > 18432 or cursor + 5 + size > len(data):
                return None
            if kind == 22:
                handshake.extend(data[cursor + 5:cursor + 5 + size])
            cursor += 5 + size
            if len(handshake) >= 4:
                if handshake[0] != 1:
                    return None
                needed = 4 + int.from_bytes(handshake[1:4], "big")
                if needed > 65536:
                    return None
                if len(handshake) >= needed:
                    return _parse_hello(bytes(handshake[4:needed]))
    except (IndexError, ValueError):
        return None
    return None


def _parse_hello(hello: bytes) -> dict | None:
    offset = 0

    def take(n: int) -> bytes:
        nonlocal offset
        if n < 0 or offset + n > len(hello):
            raise ValueError("Truncated ClientHello")
        out = hello[offset:offset + n]
        offset += n
        return out

    def u16() -> int:
        return int.from_bytes(take(2), "big")

    def vector16(raw: bytes) -> list[int]:
        if len(raw) % 2:
            raise ValueError("Odd vector")
        return [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]

    try:
        version = u16()
        take(32)
        take(take(1)[0])
        ciphers = [x for x in vector16(take(u16())) if not _grease(x)]
        take(take(1)[0])
        extensions, groups, formats = [], [], []
        if offset != len(hello):
            extension_length = u16()
            end = offset + extension_length
            if end != len(hello):
                return None
            while offset < end:
                extension = u16()
                payload = take(u16())
                if not _grease(extension):
                    extensions.append(extension)
                if extension == 10:
                    if len(payload) < 2 or int.from_bytes(payload[:2], "big") != len(payload) - 2:
                        return None
                    groups = [x for x in vector16(payload[2:]) if not _grease(x)]
                elif extension == 11:
                    if not payload or payload[0] != len(payload) - 1:
                        return None
                    formats = list(payload[1:])
        text = ",".join([str(version)] + ["-".join(map(str, values))
                        for values in (ciphers, extensions, groups, formats)])
        return {"ja3": hashlib.md5(text.encode(), usedforsecurity=False).hexdigest(),
                "ja3_string": text}
    except (ValueError, IndexError):
        return None


def make_local_certificate(directory: Path) -> tuple[Path, Path]:
    """Generate a short-lived certificate for loopback; never disable verification."""
    directory.mkdir(parents=True, exist_ok=True)
    cert, key = directory / "localhost.pem", directory / "localhost.key"
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("HTTPS needs OpenSSL on PATH. Use HTTP-only config or install OpenSSL.")
    command = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "7",
        "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError("Could not generate local certificate: " + result.stderr[-1000:])
    try:
        os.chmod(key, 0o600)
    except OSError:
        pass
    return cert, key
