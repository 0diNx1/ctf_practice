# Reverse the given encoder by prefix search with pruning.

TARGET = "6768107b1a357132741539783d6a661b5f3b"  # your hex output
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_{}"  # adjust if needed

def forward(s: bytes) -> str:
    flag = bytearray(s)
    out = []
    for i in range(len(flag)):
        if i > 0:
            flag[i] ^= flag[i-1]
        v = flag[i] & 0xFF
        v ^= (v >> 4)
        v &= 0xFF
        v ^= (v >> 3)
        v &= 0xFF
        v ^= (v >> 2)
        v &= 0xFF
        v ^= (v >> 1)
        v &= 0xFF
        flag[i] = v
        out.append(f"{v:02x}")
    return "".join(out)

def recover(target_hex: str, alphabet: str):
    n = len(target_hex) // 2  # expected length
    prefix = b""
    for pos in range(n):
        expected = target_hex[: (pos + 1) * 2]
        found = None
        for ch in alphabet:
            cand = prefix + ch.encode()
            if forward(cand) == expected:
                prefix = cand
                found = ch
                break
        if found is None:
            raise ValueError(f"No matching character at position {pos}")
    return prefix.decode()

if __name__ == "__main__":
    s = recover(TARGET, ALPHABET)
    print("Recovered:", s)

