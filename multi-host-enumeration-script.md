# Basic Multi-Host Enumeration Script

---

## 📌 Description
A Bash-based enumeration script that performs automated reconnaissance across multiple targets and generates individual reports per host.

Designed for **authorised lab environments and penetration testing practice**.

---

## 🚀 Features
- Multi-host scanning via input file
- Automated service enumeration using Nmap
- Web directory brute-forcing with Gobuster
- Service-specific enumeration:
  - HTTP/HTTPS
  - FTP
  - SSH
  - SMB
  - MySQL
  - PostgreSQL
  - NFS
- Basic vulnerability checks (e.g. SMB, TLS)
- Structured output reports per target

---

## ⚙️ Requirements

- Bash
- `nmap`
- `gobuster`
- Wordlist:
  ```
  /usr/share/wordlists/dirb/common.txt
  ```
---

## 🧠 How It Works

1. Reads targets from input file
2. Runs initial Nmap scan (`-sC -sV`)
3. Detects open ports from scan results
4. Conditionally runs:
   - Service-specific enumeration
   - Directory brute-forcing (web services)
   - Vulnerability checks
5. Saves structured output per host

---

## 📄 Script

```bash
#!/bin/bash

# ---------------------------------------
# Basic Multi-Host Enumeration Script
# Saves one report file per host
# For authorised lab use only
# Usage: ./enum.sh targets.txt
# ---------------------------------------

if [ $# -ne 1 ]; then
    echo "Usage: $0 <targets_file>"
    exit 1
fi

TARGETS_FILE="$1"
OUTPUT_DIR="scans"

mkdir -p "$OUTPUT_DIR"

write_section() {
    local title="$1"
    local outfile="$2"

    {
        echo
        echo "========================================"
        echo "$title"
        echo "========================================"
    } >> "$outfile"
}

enumerate_http() {
    local ip="$1"
    local outfile="$2"

    write_section "HTTP / HTTPS ENUMERATION" "$outfile"
    nmap -Pn -p 80,443,8080,8000 --script http-title,http-headers "$ip" >> "$outfile" 2>&1
}

enumerate_directories() {
    local ip="$1"
    local outfile="$2"
    local wordlist="/usr/share/wordlists/dirb/common.txt"

    write_section "DIRECTORY ENUMERATION" "$outfile"

    if [ ! -f "$wordlist" ]; then
        echo "[!] Wordlist not found: $wordlist" >> "$outfile"
        return
    fi

    if grep -q "80/tcp" "$outfile"; then
        echo "[*] Running directory enumeration on http://$ip:80" >> "$outfile"
        gobuster dir -u "http://$ip:80" -w "$wordlist" -q 2>/dev/null | \
            grep "Status: 200\|Status: 204\|Status: 301\|Status: 302\|Status: 307\|Status: 401\|Status: 403" >> "$outfile"
    fi

    if grep -q "443/tcp" "$outfile"; then
        echo >> "$outfile"
        echo "[*] Running directory enumeration on https://$ip:443" >> "$outfile"
        gobuster dir -u "https://$ip:443" -w "$wordlist" -k -q 2>/dev/null | \
            grep "Status: 200\|Status: 204\|Status: 301\|Status: 302\|Status: 307\|Status: 401\|Status: 403" >> "$outfile"
    fi

    if grep -q "8080/tcp" "$outfile"; then
        echo >> "$outfile"
        echo "[*] Running directory enumeration on http://$ip:8080" >> "$outfile"
        gobuster dir -u "http://$ip:8080" -w "$wordlist" -q 2>/dev/null | \
            grep "Status: 200\|Status: 204\|Status: 301\|Status: 302\|Status: 307\|Status: 401\|Status: 403" >> "$outfile"
    fi

    if grep -q "8000/tcp" "$outfile"; then
        echo >> "$outfile"
        echo "[*] Running directory enumeration on http://$ip:8000" >> "$outfile"
        gobuster dir -u "http://$ip:8000" -w "$wordlist" -q 2>/dev/null | \
            grep "Status: 200\|Status: 204\|Status: 301\|Status: 302\|Status: 307\|Status: 401\|Status: 403" >> "$outfile"
    fi
}

enumerate_ftp() {
    local ip="$1"
    local outfile="$2"

    write_section "FTP ENUMERATION" "$outfile"
    nmap -Pn -p 21 --script ftp-anon,ftp-syst "$ip" >> "$outfile" 2>&1
}

enumerate_ssh() {
    local ip="$1"
    local outfile="$2"

    write_section "SSH ENUMERATION" "$outfile"
    nmap -Pn -p 22 --script ssh-hostkey "$ip" >> "$outfile" 2>&1
}

enumerate_smb() {
    local ip="$1"
    local outfile="$2"

    write_section "SMB ENUMERATION" "$outfile"
    nmap -Pn -p 139,445 --script smb-os-discovery,smb-protocols "$ip" >> "$outfile" 2>&1
}

enumerate_mysql() {
    local ip="$1"
    local outfile="$2"

    write_section "MYSQL ENUMERATION" "$outfile"
    nmap -Pn -p 3306 --script mysql-info "$ip" >> "$outfile" 2>&1
}

enumerate_postgres() {
    local ip="$1"
    local outfile="$2"

    write_section "POSTGRESQL ENUMERATION" "$outfile"
    nmap -Pn -p 5432 --script pgsql-info "$ip" >> "$outfile" 2>&1
}

enumerate_nfs() {
    local ip="$1"
    local outfile="$2"

    write_section "NFS / RPC ENUMERATION" "$outfile"
    nmap -Pn -p 111,2049 --script rpcinfo,nfs-showmount "$ip" >> "$outfile" 2>&1
}

enumerate_vulns() {
    local ip="$1"
    local outfile="$2"

    write_section "BASIC VULNERABILITY CHECKS" "$outfile"

    if grep -q "445/tcp" "$outfile" || grep -q "139/tcp" "$outfile"; then
        echo "[*] Checking for MS17-010 / EternalBlue exposure" >> "$outfile"
        nmap -Pn -p 445 --script smb-vuln-ms17-010 "$ip" >> "$outfile" 2>&1

        echo >> "$outfile"
        echo "[*] Checking SMB security configuration" >> "$outfile"
        nmap -Pn -p 445 --script smb2-security-mode,smb-protocols "$ip" >> "$outfile" 2>&1

        echo >> "$outfile"
        echo "[*] Checking SMB OS details" >> "$outfile"
        nmap -Pn -p 445 --script smb-os-discovery "$ip" >> "$outfile" 2>&1
    fi

    if grep -q "21/tcp" "$outfile"; then
        echo >> "$outfile"
        echo "[*] Checking for anonymous FTP access" >> "$outfile"
        nmap -Pn -p 21 --script ftp-anon "$ip" >> "$outfile" 2>&1
    fi

    if grep -q "443/tcp" "$outfile"; then
        echo >> "$outfile"
        echo "[*] Checking SSL/TLS configuration" >> "$outfile"
        nmap -Pn -p 443 --script ssl-cert,ssl-enum-ciphers "$ip" >> "$outfile" 2>&1
    fi
}

while IFS= read -r ip; do
    [ -z "$ip" ] && continue

    OUTFILE="$OUTPUT_DIR/${ip}_report.txt"

    echo "[*] Enumerating $ip"
    echo "Report for $ip" > "$OUTFILE"
    echo "Generated on: $(date)" >> "$OUTFILE"

    write_section "INITIAL NMAP SCAN" "$OUTFILE"
    nmap -Pn -sC -sV "$ip" >> "$OUTFILE" 2>&1

    if grep -q "80/tcp" "$OUTFILE" || grep -q "443/tcp" "$OUTFILE" || grep -q "8080/tcp" "$OUTFILE" || grep -q "8000/tcp" "$OUTFILE"; then
        enumerate_http "$ip" "$OUTFILE"
        enumerate_directories "$ip" "$OUTFILE"
    fi

    if grep -q "21/tcp" "$OUTFILE"; then
        enumerate_ftp "$ip" "$OUTFILE"
    fi

    if grep -q "22/tcp" "$OUTFILE"; then
        enumerate_ssh "$ip" "$OUTFILE"
    fi

    if grep -q "139/tcp" "$OUTFILE" || grep -q "445/tcp" "$OUTFILE"; then
        enumerate_smb "$ip" "$OUTFILE"
    fi

    if grep -q "3306/tcp" "$OUTFILE"; then
        enumerate_mysql "$ip" "$OUTFILE"
    fi

    if grep -q "5432/tcp" "$OUTFILE"; then
        enumerate_postgres "$ip" "$OUTFILE"
    fi

    if grep -q "111/tcp" "$OUTFILE" || grep -q "2049/tcp" "$OUTFILE"; then
        enumerate_nfs "$ip" "$OUTFILE"
    fi

    enumerate_vulns "$ip" "$OUTFILE"

    write_section "END OF REPORT" "$OUTFILE"
    echo "[✓] Saved report to $OUTFILE"

done < "$TARGETS_FILE"

echo "[✓] All reports complete"
```
