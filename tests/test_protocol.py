"""Tests for the CA2 smart-meter AEAD protocol. Run: python -m pytest -v"""

import os
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from attack import attack
from src import protocol as P

ST = bytes.fromhex("4c475a000001e240")
ST2 = bytes.fromhex("4c475a000001e241")


@pytest.fixture
def setup(tmp_path):
    master = P.new_master_key()
    he = P.HeadEnd()
    he.register(ST, master)
    meter = P.make_meter(ST, master, tmp_path)
    return master, he, meter, tmp_path


# ------------------------------------------------ 1. published test vectors
GCM_K = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
GCM_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM_P = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
GCM_A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
GCM_C = bytes.fromhex(
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
GCM_T = bytes.fromhex("5bc94fbc3221a5db94fae95ae7121a47")


def test_gcm_vector_aes128_with_aad():
    """GCM spec (McGrew and Viega) Test Case 4: AES-128, 96-bit IV, AAD."""
    assert AESGCM(GCM_K).encrypt(GCM_IV, GCM_P, GCM_A) == GCM_C + GCM_T
    assert AESGCM(GCM_K).decrypt(GCM_IV, GCM_C + GCM_T, GCM_A) == GCM_P


GCM256_K = GCM_K + GCM_K
GCM256_C = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
GCM256_T = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")


def test_gcm_vector_aes256_with_aad():
    """GCM spec (McGrew and Viega) Test Case 16: AES-256, 96-bit IV, AAD.
    AES-256 is the key size the protocol uses (CA1 recommendation)."""
    assert AESGCM(GCM256_K).encrypt(GCM_IV, GCM_P, GCM_A) == GCM256_C + GCM256_T


def test_hkdf_rfc5869_case1():
    """RFC 5869 Appendix A.1, with the same HKDF configuration derive_key uses."""
    okm = HKDF(hashes.SHA256(), 42, bytes(range(13)), bytes(range(0xF0, 0xFA))).derive(b"\x0b" * 22)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db0"
                         "2d56ecc4c5bf34007208d5b887185865")


# ------------------------------------------------ 2. construction
def test_nonce_layout():
    assert P.build_nonce(ST, 5) == ST + b"\x00\x00\x00\x05"
    assert len(P.build_nonce(ST, 5)) == 12


def test_key_separation():
    m = P.new_master_key()
    keys = {P.uplink_key(m, ST), P.downlink_key(m, ST), P.uplink_key(m, ST2)}
    assert len(keys) == 3 and all(len(k) == 32 for k in keys)


def test_round_trip(setup):
    _, he, meter, _ = setup
    mt, st, ctr, pt = he.open(meter.seal(P.MSG_READING, b"RDG|kWh=1"))
    assert (mt, st, ctr, pt) == (P.MSG_READING, ST, 1, b"RDG|kWh=1")


# ------------------------------------------------ 3. negative tests (each must be rejected)
@pytest.mark.parametrize("where", ["header", "ciphertext", "tag"])
def test_bit_flip_rejected(setup, where):
    _, he, meter, _ = setup
    f = bytearray(meter.seal(P.MSG_READING, b"RDG|kWh=0012345.6"))
    idx = {"header": 1, "ciphertext": P.HEADER_LEN + 2, "tag": len(f) - 1}[where]
    f[idx] ^= 0x01
    with pytest.raises(P.FrameRejected):
        he.open(bytes(f))


def test_wrong_key_rejected(tmp_path):
    he = P.HeadEnd()
    he.register(ST, P.new_master_key())
    meter = P.make_meter(ST, P.new_master_key(), tmp_path)
    with pytest.raises(P.FrameRejected):
        he.open(meter.seal(P.MSG_READING, b"x"))


def test_replay_rejected(setup):
    _, he, meter, _ = setup
    f = meter.seal(P.MSG_READING, b"r1")
    he.open(f)
    with pytest.raises(P.FrameRejected):
        he.open(f)


def test_reorder_rejected(setup):
    _, he, meter, _ = setup
    f1, f2 = meter.seal(P.MSG_READING, b"r1"), meter.seal(P.MSG_READING, b"r2")
    he.open(f2)
    with pytest.raises(P.FrameRejected):
        he.open(f1)


def test_cut_and_paste_to_other_meter_rejected(tmp_path):
    """Header (system title) is in the AAD and the key is per-meter."""
    m = P.new_master_key()
    he = P.HeadEnd()
    he.register(ST, m)
    he.register(ST2, m)              # even with the SAME master key
    f = P.make_meter(ST, m, tmp_path).seal(P.MSG_READING, b"r1")
    hdr = P.build_header(P.MSG_READING, ST2, 1)
    with pytest.raises(P.FrameRejected):
        he.open(hdr + f[P.HEADER_LEN:])


@pytest.mark.parametrize("frame", [b"", b"\x01" * 10, b"\x01" * (P.HEADER_LEN + 15)])
def test_malformed_rejected(setup, frame):
    with pytest.raises(P.FrameRejected):
        setup[1].open(frame)


def test_rejection_is_uniform(setup):
    """Same exception and message for every failure: no error oracle."""
    _, he, meter, _ = setup
    good = meter.seal(P.MSG_READING, b"r")
    he.open(good)
    msgs = set()
    for bad in [good, good[:-1] + bytes([good[-1] ^ 1]), b"short"]:
        with pytest.raises(P.FrameRejected) as e:
            he.open(bad)
        msgs.add(str(e.value))
    assert msgs == {"rejected"}


# ------------------------------------------------ 4. state handling
def test_counter_survives_power_cycle(tmp_path):
    m = P.new_master_key()
    nonces = set()
    for _ in range(50):                               # 50 power cycles
        meter = P.make_meter(ST, m, tmp_path)
        f = meter.seal(P.MSG_READING, b"r")
        nonces.add(f[2:2 + 12])                       # system title + counter
    assert len(nonces) == 50


def test_head_end_state_survives_restart(tmp_path):
    m = P.new_master_key()
    meter = P.make_meter(ST, m, tmp_path)
    f = meter.seal(P.MSG_READING, b"r")
    he = P.HeadEnd(tmp_path / "he.state"); he.register(ST, m); he.open(f)
    he2 = P.HeadEnd(tmp_path / "he.state"); he2.register(ST, m)
    with pytest.raises(P.FrameRejected):
        he2.open(f)                                   # replay after restart


def test_refuses_to_encrypt_if_counter_cannot_be_saved(tmp_path):
    store = P.FileCounterStore(tmp_path / "missing_dir" / "c.ctr")
    meter = P.Meter(ST, P.new_master_key(), store)
    with pytest.raises(P.CounterUnavailable):
        meter.seal(P.MSG_READING, b"r")


def test_reserve_limits_flash_writes_and_skips_on_reboot(tmp_path):
    store = P.FileCounterStore(tmp_path / "c.ctr", reserve=100)
    values = [store.next() for _ in range(1000)]
    assert values == list(range(1, 1001)) and store.writes == 10
    store2 = P.FileCounterStore(tmp_path / "c.ctr", reserve=100)   # reboot
    assert store2.next() == 1001                                   # resumes above reserve


def test_reboot_mid_block_never_repeats(tmp_path):
    seen = set()
    for _ in range(20):                              # reboot after 7 frames each time
        store = P.FileCounterStore(tmp_path / "c.ctr", reserve=100)
        for _ in range(7):
            v = store.next()
            assert v not in seen
            seen.add(v)


def test_counter_exhaustion(tmp_path):
    path = tmp_path / "c.ctr"
    path.write_text(str(P.MAX_COUNTER))
    meter = P.Meter(ST, P.new_master_key(), P.FileCounterStore(path))
    with pytest.raises(P.CounterUnavailable):
        meter.seal(P.MSG_READING, b"r")


# ------------------------------------------------ 5. the attack
def test_flawed_build_repeats_nonce_after_power_cycle(tmp_path):
    m = P.new_master_key()
    f1 = P.make_meter(ST, m, tmp_path, flawed=True).seal(P.MSG_READING, b"a")
    f2 = P.make_meter(ST, m, tmp_path, flawed=True).seal(P.MSG_READING, b"b")
    assert f1[2:14] == f2[2:14]


def test_attack_succeeds_on_flawed_build():
    assert attack.run("flawed") is True


def test_attack_fails_on_correct_build():
    assert attack.run("correct") is False
