#!/usr/bin/env python3
# Full solver + candidate generator for combinations of part1 & part2
# pip install pycryptodome

from Crypto.Cipher import AES
from Crypto.Util.number import inverse, long_to_bytes
from Crypto.Util.Padding import unpad
from hashlib import sha256
from math import gcd
import base64

# ---------- Given values ----------
enc = b'\xe6\x97\x9f\xb9\xc9>\xde\x1e\x85\xbb\xebQ"Ii\xda\'\x1f\xae\x19\x05M\x01\xe1kzS\x8fi\xf4\x8cz'
a = 958181900694223
c = 1044984108221161
m = 675709840048419795804542182249
leaked_shifted = 176787694147066159797379
part2_hex = "6768107b1a357132741539783d6a661b5f3b"

# ---------- recover seed (deterministic) ----------
k = 65537
low = leaked_shifted << 20
high = (leaked_shifted + 1) << 20

ainv = inverse(a, m)
phi = m - 1
g = gcd(k, phi)

found_seed = None
if g == 1:
    k_inv = inverse(k, phi)
    for new_seed in range(low, high):
        y = ((new_seed - c) * ainv) % m
        s_candidate = pow(y, k_inv, m)
        if s_candidate < (1 << 50):
            if (a * pow(s_candidate, k, m) + c) % m == new_seed:
                found_seed = s_candidate
                break
else:
    for new_seed in range(low, high):
        y = ((new_seed - c) * ainv) % m
        if pow(y, phi // g, m) != 1:
            continue
        try:
            k_red_inv = inverse(k // g, phi // g)
        except Exception:
            continue
        base = pow(y, k_red_inv, m)
        if base < (1 << 50) and (a * pow(base, k, m) + c) % m == new_seed:
            found_seed = base
            break

if found_seed is None:
    raise RuntimeError("Seed not recovered")

print("FOUND seed:", found_seed)

key = sha256(long_to_bytes(found_seed)).digest()
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(enc)
try:
    part1_plain = unpad(decrypted, 16)
except Exception:
    part1_plain = decrypted
print("part1_plain:", part1_plain, repr(part1_plain.decode('utf-8', errors='replace')))

# ---------- reverse part2 transform (deterministic) ----------
out = bytes.fromhex(part2_hex)
# build mapping v -> list of B (it will be singletons for these v)
mapping = {}
for B in range(256):
    v = B
    v ^= (v >> 4); v &= 0xFF
    v ^= (v >> 3); v &= 0xFF
    v ^= (v >> 2); v &= 0xFF
    v ^= (v >> 1); v &= 0xFF
    mapping.setdefault(v, []).append(B)

Bs = [mapping[v][0] for v in out]   # deterministic: each out maps to exactly one B
# reconstruct original processed bytes P (P[0]=B0; P[i] = Bi ^ P[i-1])
P = []
for i, b in enumerate(Bs):
    if i == 0:
        P.append(b)
    else:
        P.append(b ^ P[i-1])
recovered_part2 = bytes(P)

print("recovered_part2 (raw bytes):", recovered_part2)
print("recovered_part2 hex:", recovered_part2.hex())

# ---------- generate candidate flag formats ----------
candidates = []

s1 = part1_plain.decode('latin1')  # keep bytes as-is if non-utf8
p2_hex = recovered_part2.hex()
p2_b64 = base64.b64encode(recovered_part2).decode()
p2_escaped = ''.join('\\x%02x' % b for b in recovered_part2)

# common combos:
candidates.append(s1 + recovered_part2.decode('latin1'))
candidates.append(s1 + p2_hex)
candidates.append(s1 + "_" + p2_hex)
candidates.append(s1 + p2_b64)
candidates.append(s1 + "_" + p2_b64)
candidates.append(s1 + p2_escaped)
candidates.append(s1 + "_" + p2_escaped)
# maybe the second part is to be appended as raw bytes but encoded hex inside braces:
candidates.append(s1 + "{" + p2_hex + "}")
# maybe XOR second part with ASCII template to get printable suffix (try XOR with ASCII printable bytes from known phrase length)
# attempt XOR with 'th4t_y0u_h4ve_t0_f1nd' if lengths match or truncated
try:
    template = b"th4t_y0u_h4ve_t0_f1nd"
    xorred = bytes(x ^ y for x,y in zip(recovered_part2, template))
    candidates.append(s1 + xorred.decode('latin1'))
except Exception:
    pass

# print candidates
print("\nCandidate flag strings (try submits):\n")
for idx,c in enumerate(candidates,1):
    print(f"{idx:02d}: {repr(c)}")

print("\nIf none of these match the CTF, tell me how the two parts are expected to be combined (concatenate/raw/hex/base64/XOR) and I will try exactly that. If you want, I can also try a few automated brute-force transforms (single-byte XOR, ROT, etc.) on recovered_part2 and print results.")
