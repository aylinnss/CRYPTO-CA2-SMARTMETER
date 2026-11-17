# CA2 — Implementation and Cryptanalysis of a Cryptographic Protocol

AES-256-GCM protection for smart-meter uplink frames, following the CA1 design
(Irish utility, 400,000 meters), a deliberately flawed build, and an attack that breaks it.

* **Correct build:** the GCM invocation counter is kept in non-volatile storage
  with a reserve (CA1): a ceiling 100 values ahead is written and fsync'd *before*
  any value above the old ceiling is used, so after a simulated restart counter
  values may be skipped but are not reused.
* **Flawed build:** the counter is kept only in RAM (`MemoryCounterStore`), so it
  restarts at 1 after every power cycle and the 12-byte nonce repeats.
* **Attack:** a customer who can power-cycle the meter and record its traffic
  recovers a secret tamper alarm from one known reading (keystream reuse).
  No key is used.

The one line that differs between builds is in `src/protocol.py`, `make_meter()`:

```diff
-        store = FileCounterStore(Path(state_dir) / f"{system_title.hex()}.ctr")
+        store = MemoryCounterStore()          # FLAW: counter lives only in RAM
```

## Requirements

* Python 3.12 or later (tested on Python 3.12.6 on Windows 11; see `results.txt`)
* Dependencies pinned in `requirements.txt`: `cryptography==50.0.1`, `pytest==9.1.1`
* After the dependencies are installed, everything runs offline. The code contains no absolute paths,
  and no keys are stored in the repository (keys are generated from the operating
  system's random number generator on every run).

## Install

Windows, Command Prompt (`cmd`):

```
py -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

Windows, PowerShell: the same, but activate with `.venv\Scripts\Activate.ps1`.

On the test machine, whose project path contains `&`, running `activate.bat` from
Command Prompt failed. If that happens, the virtual environment's own interpreter can
be used directly without activating it:

```
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe run_all.py
```

Linux / macOS:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run (from the repository root)

| What | Command | Make |
|---|---|---|
| Normal protocol operation | `python -m src.run` | `make run` |
| Attack against the **flawed** build | `python -m attack.attack --build flawed` | `make attack` |
| Same attack against the **correct** build | `python -m attack.attack --build correct` | `make attack-correct` |
| Test suite (26 tests) | `python -m pytest -v` | `make test` |
| **Everything above, saved to `results.txt`** | `python run_all.py` | |

The attack exits with code **0** on success and **1** on failure.

`run_all.py` overwrites `results.txt`. The submitted `results.txt` is the Windows 11
run reproduced in Appendix A of the report; copy it elsewhere before re-running if
you want to keep it.

### Expected output — flawed build

```
=== build: FLAWED ===
[wire] frame 1 nonce=4c475a000001e24000000001  recorded; head-end accepted (counter 1)
[attacker] power-cycles the meter
[wire] frame 2 nonce=4c475a000001e24000000001  recorded; head-end REJECTED
[attacker] nonce reuse visible in headers: True
[attacker] recovered P2 : b'ALM|TAMPER=COVER_OPEN|PWR=RESTORED|v=2'
[harness ] true      P2 : b'ALM|TAMPER=COVER_OPEN|PWR=RESTORED|v=2'
[result  ] CONFIDENTIALITY broken: True
ATTACK SUCCEEDED
```

The head-end rejects frame 2 as a replay, but the ciphertext is already on the wire,
so the secret leaks anyway.

### Expected output — correct build

```
=== build: CORRECT ===
[wire] frame 2 nonce=4c475a000001e24000000065  recorded; head-end accepted (counter 101)
[attacker] nonce reuse visible in headers: False
[attacker] recovered P2 : b'\x1f\xbb...'          (random bytes)
[result  ] CONFIDENTIALITY broken: False
ATTACK FAILED
```

The recovered bytes differ on every run because keys are random; the result does not.

## Layout

```
src/protocol.py     correct implementation + the one-line flaw switch (make_meter)
src/run.py          normal-operation demo
attack/attack.py    attacker logic (frames + one known plaintext only) and scenario harness
tests/              GCM and HKDF test vectors, negative tests, state tests, attack tests
run_all.py          runs every step and writes results.txt
results.txt         submitted output of run_all.py on Windows 11 (overwritten on re-run)
smart_meter.py      minimal counter exercise showing the counter reset and XOR recovery
```
