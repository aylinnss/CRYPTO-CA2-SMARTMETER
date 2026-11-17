from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = AESGCM.generate_key(bit_length=256)
aead = AESGCM(key)
meter_id = b"METER001"
counter = 0
def seal(reading):
    global counter
    counter = counter + 1
    nonce = meter_id + counter.to_bytes(4, "big")
    return nonce, aead.encrypt(nonce, reading, None)

nonce1, sealed1 = seal(b"READING 12345 kWh")
nonce2, sealed2 = seal(b"READING 12346 kWh")
print("Reading 1 nonce:", nonce1.hex())
print("Reading 2 nonce:", nonce2.hex())

print("--- POWER CUT ---")
counter = 0
nonce3, sealed3 = seal(b"ALARM COVER OPEN!")
print("Alarm nonce:    ", nonce3.hex())

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

known = b"READING 12345 kWh"
secret = xor(xor(sealed1[:17], sealed3[:17]), known)
print("Attacker found:", secret)
