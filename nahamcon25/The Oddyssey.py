from pwn import *

# Connect to the server
conn = remote("server", port)

try:
    while True:
        # Receive until the "Press enter to continue..." marker
        data = conn.recvuntil(b"Press enter to continue...").decode(errors="ignore")
        print(data)  # Optional: print for visibility

        # Check for a flag pattern — case-insensitive and robust
        if "flag{" in data.lower():
            # Extract everything that looks like a flag
            import re
            flags = re.findall(r'flag\{.*?\}', data, re.IGNORECASE)
            for flag in flags:
                print("FLAG FOUND:", flag)
            break

        # Press Enter
        conn.sendline(b'')

except EOFError:
    print("[!] Connection closed by remote host.")

finally:
    conn.close()
