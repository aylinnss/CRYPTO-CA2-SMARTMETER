"""
CA2 attack: GCM nonce reuse after a meter power cycle (confidentiality).

Threat model given to the attacker (and nothing more), from CA1 Table A1
("fraudulent customer", "customer tampering"):
  * Passive position on the meter's uplink: it records every frame.
  * Physical access to the meter's power supply (it can cut the power).
  * One known plaintext: the reading shown on the meter's own display.
  * NO keys, NO access to meter or head-end memory.

The same script is run against both builds:
    python -m attack.attack --build flawed    -> succeeds, exit code 0
    python -m attack.attack --build correct   -> fails,    exit code 1
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import time

from src import protocol as P

ST = bytes.fromhex("4c475a000001e240")   # meter system title
H_LEN, TAG = P.HEADER_LEN, P.TAG_LEN


# =========================================================================
# ATTACKER LOGIC - sees only frames on the wire and one known plaintext
# =========================================================================
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def nonce_of(frame: bytes) -> bytes:
    """The nonce is public: system title and counter travel in the header."""
    _, _, st, ctr, _ = P.parse_header(frame[:H_LEN])
    return P.build_nonce(st, ctr)


def ciphertext_of(frame: bytes) -> bytes:
    return frame[H_LEN:-TAG]


def recover_plaintext(f1: bytes, f2: bytes, known_p1: bytes) -> bytes:
    """Same key + same nonce = same keystream, so C1 xor C2 = P1 xor P2
    and P2 = C1 xor C2 xor P1."""
    return xor(xor(ciphertext_of(f1), ciphertext_of(f2)), known_p1)


# =========================================================================
# SCENARIO HARNESS - plays the honest meter and head-end (it holds the keys;
# the attacker functions above never see them)
# =========================================================================
def run(build: str) -> bool:
    flawed = build == "flawed"
    with tempfile.TemporaryDirectory(prefix="ca2-") as state:
        master = P.new_master_key()
        head_end = P.HeadEnd()
        head_end.register(ST, master)
        print(f"=== build: {build.upper()} ===")

        # 1. Meter boots and sends a reading. The customer can read the same
        #    value on the meter display -> known plaintext.
        meter = P.make_meter(ST, master, state, flawed=flawed)
        p1 = b"RDG|kWh=0012345.6|ts=2026-11-13T21:00Z"
        f1 = meter.seal(P.MSG_READING, p1)
        deliver(head_end, f1, 1)

        # 2. Attacker cuts the meter's power. Meter reboots.
        print("[attacker] power-cycles the meter")
        meter = P.make_meter(ST, master, state, flawed=flawed)

        # 3. On power-up the meter reports a tamper alarm (secret to attacker).
        p2 = b"ALM|TAMPER=COVER_OPEN|PWR=RESTORED|v=2"
        f2 = meter.seal(P.MSG_ALARM, p2)
        deliver(head_end, f2, 2)

        # ------------------------------------------------------------ attack
        t0 = time.perf_counter()
        reused = nonce_of(f1) == nonce_of(f2)
        recovered = recover_plaintext(f1, f2, p1)
        elapsed = time.perf_counter() - t0
        success = recovered == p2[:len(recovered)]

        print(f"[attacker] nonce reuse visible in headers: {reused}")
        print(f"[attacker] recovered P2 : {recovered!r}")
        print(f"[harness ] true      P2 : {p2!r}")
        print(f"[result  ] CONFIDENTIALITY broken: {success}")
        print(f"[cost    ] frames recorded=2, known plaintexts=1, "
              f"attacker time={elapsed * 1000:.3f} ms")
    return success


def deliver(head_end: P.HeadEnd, frame: bytes, n: int) -> None:
    try:
        _, _, ctr, _ = head_end.open(frame)
        verdict = f"accepted (counter {ctr})"
    except P.FrameRejected:
        verdict = "REJECTED"
    print(f"[wire] frame {n} nonce={nonce_of(frame).hex()}  "
          f"recorded; head-end {verdict}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", choices=["flawed", "correct"], required=True)
    success = run(ap.parse_args().build)
    print("ATTACK SUCCEEDED" if success else "ATTACK FAILED")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
