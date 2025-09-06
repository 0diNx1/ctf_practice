from sympy import factorint, ilcm, primerange
from Crypto.Cipher import AES
from binascii import unhexlify

n = 107502945843251244337535082460697583639357473016005252008262865481138355040617
primes = list(primerange(0, 100))
ct_hex = "b6c4d050dd08fd8471ef06e73d39b359e3fc370ca78a3426f01540985b88ba66ec9521e9b68821fed1fa625e11315bf9"

def carmichael(m):
    fac = factorint(m)
    parts = []
    for p, e in fac.items():
        if p == 2 and e >= 3:
            parts.append(2**(e-2))
        else:
            parts.append((p-1)*p**(e-1))
    lam = 1
    for a in parts:
        lam = ilcm(lam, a)
    return lam

def tower_mod(prime_list, mod, huge_threshold=10**6):
    if mod == 1: return 0, True, None
    if not prime_list: return 1 % mod, False, 1
    lam = carmichael(mod)
    prev_mod, prev_huge, prev_exact = tower_mod(prime_list[:-1], lam, huge_threshold)
    exp = prev_mod + (lam if prev_huge else 0)
    base = prime_list[-1]
    val_mod = pow(base, exp, mod)
    if prev_huge:
        return val_mod, True, None
    actual = base ** prev_exact
    return val_mod, (actual > huge_threshold), (None if actual > huge_threshold else actual)

int_key_mod, _, _ = tower_mod(primes, n)
key = int_key_mod.to_bytes(32, "big")
pt = AES.new(key, AES.MODE_ECB).decrypt(unhexlify(ct_hex))
print(pt.rstrip(b"_").decode())
