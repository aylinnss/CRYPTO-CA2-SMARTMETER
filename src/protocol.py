"""
CA2 - Authenticated encryption for smart-meter uplink frames.

Scenario (CA1): an Irish utility with 400,000 smart meters. Each meter sends
readings and alarms to the utility head-end. Frames are protected with
AES-256-GCM (the CA1 recommendation, DLMS/COSEM Suite 2) in a DLMS/COSEM-style construction:

    nonce (12 bytes) = system_title (8 bytes) || invocation_counter (4 bytes)

Frame layout (all integers big-endian):

    +---------+----------+--------------+---------+---------+------------+-----+
    | version | msg_type | system_title | counter | key_ver | ciphertext | tag |
    |   1 B   |   1 B    |     8 B      |   4 B   |   1 B   |    n B     | 16B |
    +---------+----------+--------------+---------+---------+------------+-----+
    |<------------- header = associated data (15 bytes) -------------->|

Every header field the receiver relies on is authenticated as associated
data. Primitives (AES-GCM, HKDF-SHA256, CSPRNG) come from the pyca
`cryptography` library; nothing cryptographic is implemented here.

The ONLY difference between the correct and the flawed build is the counter
store chosen in `make_meter()` (see FLAW below).
"""

from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VERSION = 0x01
KEY_VERSION = 0x01
HEADER_FMT = ">BB8sIB"                    # version, msg_type, system_title, counter, key_ver
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 15 bytes
TAG_LEN = 16
MAX_COUNTER = 0xFFFFFFFF                  # 32-bit invocation counter

MSG_READING = 0x01
MSG_ALARM = 0x02


class FrameRejected(Exception):
    """Single, uniform rejection error. The receiver never says WHY a frame
    was rejected (bad tag, replay, bad format), so it is not an oracle."""


class CounterUnavailable(Exception):
    """The sender cannot guarantee a fresh nonce, so it refuses to encrypt."""


# --------------------------------------------------------------------------
# Key derivation: one provisioned master key per meter, separate keys per
# direction and purpose via HKDF labels (RFC 5869).
# --------------------------------------------------------------------------
def derive_key(master_key: bytes, system_title: bytes, label: bytes) -> bytes:
    """Derive a 256-bit AES-GCM key bound to this meter and this purpose.

    master_key is the input keying material. In the CA1 design this is the
    secret from the daily certificate-authenticated ECDH exchange; the key
    exchange itself is outside CA2's scope, so here it is a random 256-bit
    value shared by meter and head-end."""
    if len(master_key) < 32:
        raise ValueError("master key must be at least 256 bits")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,                        # AES-256 (CA1: DLMS Suite 2 profile)
        salt=system_title,                # binds the key to the meter identity
        info=b"CA2-smartmeter|" + label + b"|v1",
    )
    return hkdf.derive(master_key)


def uplink_key(master_key: bytes, system_title: bytes) -> bytes:
    return derive_key(master_key, system_title, b"uplink-enc")


def downlink_key(master_key: bytes, system_title: bytes) -> bytes:
    return derive_key(master_key, system_title, b"downlink-enc")


# --------------------------------------------------------------------------
# Header / nonce construction
# --------------------------------------------------------------------------
def build_header(msg_type: int, system_title: bytes, counter: int) -> bytes:
    return struct.pack(HEADER_FMT, VERSION, msg_type, system_title, counter, KEY_VERSION)


def parse_header(header: bytes):
    return struct.unpack(HEADER_FMT, header)


def build_nonce(system_title: bytes, counter: int) -> bytes:
    """12-byte GCM IV: fixed field (system title) || invocation field (counter).
    Deterministic construction, SP 800-38D section 8.2.1."""
    return system_title + struct.pack(">I", counter)


# --------------------------------------------------------------------------
# Counter stores
# --------------------------------------------------------------------------
class FileCounterStore:
    """Durable counter with a reserve (CA1, section 3).

    The store persists a CEILING, not every value. Before the first value
    above the current ceiling is used, a new ceiling (+reserve) is written and
    fsync'd. After a simulated restart the meter resumes above the stored
    ceiling, so up to `reserve` values are skipped and none is reused.
    With reserve=100 the counter state is updated once per 100 frames
    (about once a day at an assumed 96 frames a day)."""

    def __init__(self, path: str | Path, reserve: int = 100):
        if reserve < 1:
            raise ValueError("reserve must be >= 1")
        self.path = Path(path)
        self.reserve = reserve
        self.writes = 0                     # flash writes, for the wear analysis
        self._next: int | None = None       # next value to hand out (RAM)
        self._ceiling = 0                   # highest value already reserved on disk

    def _read(self) -> int:
        try:
            return int(self.path.read_text().strip())
        except FileNotFoundError:
            return 0

    def _persist(self, value: int) -> None:
        """Atomic write: temp file + fsync + rename. Raises CounterUnavailable."""
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(dir=self.path.parent)
            with os.fdopen(fd, "w") as f:
                f.write(str(value))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            self.writes += 1
        except OSError as exc:
            if tmp:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            raise CounterUnavailable("cannot persist counter; refusing to encrypt") from exc

    def next(self) -> int:
        if self._next is None:              # first use after boot
            self._ceiling = self._read()
            self._next = self._ceiling + 1  # resume ABOVE everything reserved
        value = self._next
        if value > MAX_COUNTER:
            raise CounterUnavailable("counter exhausted: re-key required")
        if value > self._ceiling:           # reserve a new block BEFORE use
            new_ceiling = min(self._ceiling + self.reserve, MAX_COUNTER)
            self._persist(new_ceiling)
            self._ceiling = new_ceiling
        self._next = value + 1
        return value


class MemoryCounterStore:
    """Counter kept only in RAM. Lost (reset to 0) on every power cycle.
    Used ONLY by the deliberately flawed build."""

    def __init__(self):
        self.value = 0

    def next(self) -> int:
        self.value += 1
        if self.value > MAX_COUNTER:
            raise CounterUnavailable("counter exhausted: re-key required")
        return self.value


# --------------------------------------------------------------------------
# Sender (meter) and receiver (head-end)
# --------------------------------------------------------------------------
class Meter:
    def __init__(self, system_title: bytes, master_key: bytes, counter_store):
        if len(system_title) != 8:
            raise ValueError("system title must be 8 bytes")
        self.system_title = system_title
        self._aead = AESGCM(uplink_key(master_key, system_title))
        self._counter = counter_store

    def seal(self, msg_type: int, plaintext: bytes) -> bytes:
        counter = self._counter.next()                  # persisted before use
        header = build_header(msg_type, self.system_title, counter)
        nonce = build_nonce(self.system_title, counter)
        return header + self._aead.encrypt(nonce, plaintext, header)


class HeadEnd:
    """Receiver. Keeps, per meter, the highest counter it has accepted and
    rejects anything not strictly greater (replay and reordering)."""

    def __init__(self, state_path: str | Path | None = None):
        self._keys: dict[bytes, AESGCM] = {}
        self._last: dict[bytes, int] = {}
        self._state_path = Path(state_path) if state_path else None
        if self._state_path and self._state_path.exists():
            for line in self._state_path.read_text().splitlines():
                st, c = line.split(":")
                self._last[bytes.fromhex(st)] = int(c)

    def register(self, system_title: bytes, master_key: bytes) -> None:
        self._keys[system_title] = AESGCM(uplink_key(master_key, system_title))
        self._last.setdefault(system_title, 0)

    def _persist(self) -> None:
        if self._state_path:                       # atomic: temp file + fsync + rename
            data = "\n".join(f"{k.hex()}:{v}" for k, v in self._last.items())
            tmp = self._state_path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._state_path)

    def open(self, frame: bytes) -> tuple[int, bytes, int, bytes]:
        """Return (msg_type, system_title, counter, plaintext) or raise FrameRejected."""
        if len(frame) < HEADER_LEN + TAG_LEN:
            raise FrameRejected("rejected")
        header, body = frame[:HEADER_LEN], frame[HEADER_LEN:]
        version, msg_type, system_title, counter, key_ver = parse_header(header)
        aead = self._keys.get(system_title)
        if version != VERSION or key_ver != KEY_VERSION or aead is None:
            raise FrameRejected("rejected")
        nonce = build_nonce(system_title, counter)
        try:
            plaintext = aead.decrypt(nonce, body, header)   # tag verified first
        except InvalidTag:
            raise FrameRejected("rejected") from None
        # Freshness: only after authentication, so an attacker cannot move the window.
        if counter <= self._last[system_title]:
            raise FrameRejected("rejected")
        self._last[system_title] = counter
        self._persist()
        return msg_type, system_title, counter, plaintext


# --------------------------------------------------------------------------
# Build selection. FLAW: this is the single line that differs.
# --------------------------------------------------------------------------
def make_meter(system_title: bytes, master_key: bytes, state_dir: str | Path,
               flawed: bool = False) -> Meter:
    """Simulate (re)booting a meter. Called again after every power cycle."""
    if flawed:
        store = MemoryCounterStore()          # FLAW: counter lives only in RAM
    else:
        store = FileCounterStore(Path(state_dir) / f"{system_title.hex()}.ctr")
    return Meter(system_title, master_key, store)


def new_master_key() -> bytes:
    return os.urandom(32)                      # OS CSPRNG
