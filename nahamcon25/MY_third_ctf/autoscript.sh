#!/bin/bash

# Color variables for godd looking
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Base URL
BASE_URL="the_url"

# Wordlists
WORDLISTS=("wrdl.txt" "wrd24.txt" "wrd23.txt" "wrd22.txt")
PATHS=("FUZZ" "qbhf/FUZZ" "qbhf/oguucig/FUZZ" "qbhf/oguucig/wrnhq/FUZZ")
FINAL_PATH="qbhf/oguucig/wrnhq/lewl/"

# Function to run ffuf with progress
run_ffuf() {
    local url="$1"
    local wordlist="$2"

    echo -e "${YELLOW}[+] Running ffuf on:${NC} $url with wordlist: $wordlist"
    ffuf -u "$BASE_URL/$url" -w "$wordlist" -t 40 -mc 200
    echo -e "${BLUE}----------------------------------------${NC}"
}

# Banner
echo -e "${GREEN}"
echo "___[[[[[------0xodinx--------____]]]]]]]"
echo "NahamCon2k25 FFUF Automation Script"
echo -e "${NC}"

# Main loop to run ffuf
for i in "${!WORDLISTS[@]}"; do
    run_ffuf "${PATHS[$i]}" "${WORDLISTS[$i]}"
done

# Fetching final flag with curl and grep
echo -e "${YELLOW}[+] Fetching the final flag from:${NC} $BASE_URL/$FINAL_PATH"
FLAG=$(curl -s "$BASE_URL/$FINAL_PATH" | grep -oP 'flag{.*?}')
echo -e "${GREEN}[+] Flag Found:${NC} ${RED}$FLAG${NC}"
