"""Normal operation demo: a meter sends readings through two power cycles.
Run: python -m src.run"""

import tempfile

from src import protocol as P

ST = bytes.fromhex("4c475a000001e240")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ca2-run-") as state:
        master = P.new_master_key()
        head_end = P.HeadEnd()
        head_end.register(ST, master)
        kwh = 12345.6
        for boot in range(3):
            meter = P.make_meter(ST, master, state)          # correct build
            for _ in range(2):
                kwh += 0.4
                frame = meter.seal(P.MSG_READING, f"RDG|kWh={kwh:09.1f}".encode())
                _, _, ctr, pt = head_end.open(frame)
                print(f"boot {boot}  counter={ctr}  nonce={P.build_nonce(ST, ctr).hex()}"
                      f"  head-end accepted {pt.decode()}")
            print("-- power cycle --")
        try:
            head_end.open(frame)
        except P.FrameRejected:
            print("replay of last frame: REJECTED")


if __name__ == "__main__":
    main()
