# pip install gmpy2
import gmpy2 as g
from gmpy2 import mpz, invert, powmod
from math import isqrt

n = mpz(10192317563100435820324883212732654109601026477813807473477878848573139071076450236118688980932037415251346520514542138140609060252895351951720245780911857)
gift = mpz(9849116110348955789479010194217500434924628821283154420120653296317850482069813955763227679617407203690983933060408814831540731516918111919543171982943742)
cipher = mpz(5233505605717906572820704125698007884756899600546277154250677229608622104923213916257278306210268480306253062577662108243267456434157595354492257249291619)
e_pub = mpz(6680156158150988373642322463932951077800266014102151350333710885437380635984671611153081168925510577011108052179392804404171397616499204018327041380331715)
g_big = mpz(79311846630906367242578569989060951934653320046283047846150092277845194835891)

print("Itz takes time to decode the flag................):\n")
print("Use python multiprocessing for better.......):\n")

# Generate all 28-bit primes [2^27, 2^28)
LOW = mpz(1) << 27
HIGH = mpz(1) << 28

def next_prime_at_least(x):
    if x <= 2: return mpz(2)
    p = g.next_prime(mpz(x))
    return p

# Pass 1: build dictionary A(p) -> p for all 28-bit primes
ap_to_p = {}
p = next_prime_at_least(LOW)
count = 0
while p < HIGH:
    Ap = powmod(p, 13, n)
    ap_to_p[Ap] = int(p)  
    p = g.next_prime(p+1)
    count += 1

# Pass 2: for each p1, compute target A(p2) = gift * inv(A(p1)) mod n and look up
p1 = next_prime_at_least(LOW)
pair_found = None
while p1 < HIGH:
    A1 = powmod(p1, 13, n)
    try:
        invA1 = invert(A1, n)
        if invA1 == 0:  # non-invertible (rare)
            p1 = g.next_prime(p1+1)
            continue
    except ZeroDivisionError:
        p1 = g.next_prime(p1+1)
        continue

    target = (gift * invA1) % n  # should equal A(p2)
    p2 = ap_to_p.get(target)
    if p2 is not None:
        pair_found = (int(p1), int(p2))
        break
    p1 = g.next_prime(p1+1)

if pair_found is None:
    raise SystemExit("No (p1,p2) pair found. (fu*kup).")

p1, p2 = pair_found
# Build d = g * p1 * p2
d = g_big * p1 * p2

#Part of Decrypt and decode
m = powmod(cipher, d, n)
def long_to_bytes(x):
    # minimal big-endian byte string
    blen = (x.bit_length() + 7) // 8
    return int(x).to_bytes(blen, 'big')

pt = long_to_bytes(m)
# print --->>utf-8 print; if!, show hex as well
try:
    print(f"here is the utf-8 of flag: {pt.decode('utf-8')}")
except UnicodeDecodeError:
    print(f"here is the raw bytes of flag: {pt}")
    print(f"here is the hex of flag: {pt.hex()}")



