def build_correct_flag():
    encrypted = [16, 49, 14, 21, 7, 48, 49, 15, 6, 48, 44, 10, 12, 49, 20, 0, 23]
    key = 51
    
    # From the output, we have these options for each position after "v1t{":
    # Position 4 (enc=7): ['m']
    # Position 5 (enc=48): ['0', 'c'] 
    # Position 6 (enc=49): ['1', 'd']
    # Position 7 (enc=15): ['u']
    # Position 8 (enc=6): ['9', 'l']
    # Position 9 (enc=48): ['0', 'c']
    # Position 10 (enc=44): ['_']
    # Position 11 (enc=10): ['p']
    # Position 12 (enc=12): ['r']
    # Position 13 (enc=49): ['1', 'd']
    # Position 14 (enc=20): ['z']
    # Position 15 (enc=0): ['3', 'f']
    # Position 16 (enc=23): ['}']
    
    # Let's build meaningful combinations:
    possibilities = [
        ['m'],           # 4
        ['0', 'c'],      # 5  
        ['1', 'd'],      # 6
        ['u'],           # 7
        ['9', 'l'],      # 8
        ['0', 'c'],      # 9
        ['_'],           # 10
        ['p'],           # 11
        ['r'],           # 12
        ['1', 'd'],      # 13
        ['z'],           # 14
        ['3', 'f'],      # 15
        ['}']            # 16
    ]
    
    print("Building meaningful flag combinations:")
    print("=" * 50)
    
    # Try different combinations that spell real words
    test_combinations = [
        # Try: m0duL0_pr1z3} but we need to match the encryption
        ["m", "0", "d", "u", "l", "0", "_", "p", "r", "1", "z", "3", "}"],  # m0dul0_pr1z3}
        ["m", "0", "d", "u", "9", "0", "_", "p", "r", "1", "z", "3", "}"],  # m0du90_pr1z3}
        ["m", "c", "d", "u", "l", "c", "_", "p", "r", "d", "z", "f", "}"],  # mcdulc_prdzf}
        ["m", "0", "1", "u", "9", "0", "_", "p", "r", "1", "z", "3", "}"],  # m01u90_pr1z3}
    ]
    
    for i, combo in enumerate(test_combinations):
        flag = "v1t{" + "".join(combo)
        # Verify this flag matches the encryption
        valid = True
        for j, char in enumerate(flag):
            if ord(char) % key != encrypted[j]:
                valid = False
                break
        
        if valid:
            print(f"✓ Valid flag: {flag}")
        else:
            print(f"✗ Invalid: {flag}")
    
    # Let me also try to find the exact match by checking each position
    print("\nFinding exact match:")
    print("=" * 30)
    
    # We know it starts with "v1t{" and ends with "}"
    # Let's find the exact characters that work
    
    exact_flag = ["v", "1", "t", "{"]
    
    # Position 4: only 'm' works
    exact_flag.append("m")
    
    # Position 5: try both '0' and 'c'
    # Position 6: try both '1' and 'd' 
    # Let's find what makes sense
    
    # Common CTF flag patterns: "m0d", "m1d", "mc?", "md?"
    
    # Try: m0d
    if ord('0') % key == encrypted[5] and ord('d') % key == encrypted[6]:
        exact_flag.extend(["0", "d"])
        print("Found: m0d")
    elif ord('c') % key == encrypted[5] and ord('1') % key == encrypted[6]:
        exact_flag.extend(["c", "1"]) 
        print("Found: mc1")
    
    # Position 7: only 'u' works
    exact_flag.append("u")
    
    # Position 8: try '9' and 'l'
    # Position 9: try '0' and 'c'
    
    # Common patterns: "L0", "90", "lc", "9c"
    
    # Check what works
    if ord('l') % key == encrypted[8] and ord('0') % key == encrypted[9]:
        exact_flag.extend(["l", "0"])
        print("Found: l0")
    elif ord('9') % key == encrypted[8] and ord('0') % key == encrypted[9]:
        exact_flag.extend(["9", "0"])
        print("Found: 90")
    
    # Position 10: only '_' works
    exact_flag.append("_")
    
    # Position 11: only 'p' works
    exact_flag.append("p")
    
    # Position 12: only 'r' works  
    exact_flag.append("r")
    
    # Position 13: try '1' and 'd'
    # Position 14: only 'z' works
    # Position 15: try '3' and 'f'
    # Position 16: only '}' works
    
    if ord('1') % key == encrypted[13]:
        exact_flag.append("1")
    else:
        exact_flag.append("d")
    
    exact_flag.append("z")
    
    if ord('3') % key == encrypted[15]:
        exact_flag.append("3")
    else:
        exact_flag.append("f")
    
    exact_flag.append("}")
    
    final_flag = "".join(exact_flag)
    
    # Verify
    valid = True
    for i, char in enumerate(final_flag):
        if ord(char) % key != encrypted[i]:
            valid = False
            print(f"Position {i}: '{char}' failed verification")
            break
    
    if valid:
        print(f"\n🎯 FINAL FLAG: {final_flag}")
    else:
        print(f"\nFlag verification failed: {final_flag}")

build_correct_flag()
