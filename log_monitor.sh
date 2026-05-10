#!/bin/bash
# =============================================================
# DevSecOps Log Monitor v1.0
# Detects: failed SSH logins, brute force attempts, suspicious IPs
# Usage: ./log_monitor.sh /var/log/auth.log
# =============================================================

LOG_FILE="${1:-/var/log/auth.log}"
THRESHOLD=5
ALERT_EMAIL="security@yourcompany.com"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Color codes for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "============================================"
echo " DevSecOps Security Log Monitor"
echo " Scan Time: $TIMESTAMP"
echo " Log File:  $LOG_FILE"
echo "============================================"

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}[ERROR]${NC} Log file not found: $LOG_FILE"
    echo "Creating sample log for demonstration..."
    
    # Generate sample auth log for practice
    cat > /tmp/sample_auth.log << 'SAMPLE'
Jan 10 09:15:22 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 09:15:25 server sshd[1235]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 09:15:28 server sshd[1236]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 09:15:30 server sshd[1237]: Failed password for admin from 10.0.0.55 port 22 ssh2
Jan 10 09:15:33 server sshd[1238]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 09:15:35 server sshd[1239]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 09:15:38 server sshd[1240]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 10 09:16:01 server sshd[1241]: Accepted password for deploy from 10.0.0.10 port 22 ssh2
Jan 10 09:16:15 server sshd[1242]: Failed password for ubuntu from 203.0.113.42 port 22 ssh2
Jan 10 09:16:18 server sshd[1243]: Failed password for ubuntu from 203.0.113.42 port 22 ssh2
Jan 10 09:16:20 server sshd[1244]: Failed password for ubuntu from 203.0.113.42 port 22 ssh2
Jan 10 09:17:00 server sshd[1245]: Failed password for test from 198.51.100.7 port 22 ssh2
SAMPLE
    LOG_FILE="/tmp/sample_auth.log"
    echo -e "${GREEN}[OK]${NC} Using sample log: $LOG_FILE"
    echo ""
fi

# --- ANALYSIS 1: Count total failed attempts ---
echo ""
echo -e "${YELLOW}[1] FAILED LOGIN SUMMARY${NC}"
echo "-------------------------------------------"
TOTAL_FAILED=$(grep -c "Failed password" "$LOG_FILE")
echo "Total failed login attempts: $TOTAL_FAILED"

# --- ANALYSIS 2: Top offending IPs ---
echo ""
echo -e "${YELLOW}[2] TOP OFFENDING IP ADDRESSES${NC}"
echo "-------------------------------------------"
echo "Count | IP Address"
echo "------+-----------------"
grep "Failed password" "$LOG_FILE" \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort \
    | uniq -c \
    | sort -rn \
    | head -10 \
    | while read count ip; do
        if [ "$count" -ge "$THRESHOLD" ]; then
            echo -e "  ${RED}${count}${NC}   | ${RED}${ip}${NC} *** BRUTE FORCE DETECTED ***"
        else
            echo "  ${count}   | ${ip}"
        fi
    done

# --- ANALYSIS 3: Targeted usernames ---
echo ""
echo -e "${YELLOW}[3] TARGETED USERNAMES${NC}"
echo "-------------------------------------------"
grep "Failed password" "$LOG_FILE" \
    | grep -oP 'for \K\w+' \
    | sort \
    | uniq -c \
    | sort -rn

# --- ANALYSIS 4: Brute force detection ---
echo ""
echo -e "${YELLOW}[4] BRUTE FORCE ALERTS${NC}"
echo "-------------------------------------------"
BRUTE_FORCE_IPS=$(grep "Failed password" "$LOG_FILE" \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort \
    | uniq -c \
    | sort -rn \
    | awk -v threshold="$THRESHOLD" '$1 >= threshold {print $2}')

if [ -z "$BRUTE_FORCE_IPS" ]; then
    echo -e "${GREEN}[OK]${NC} No brute force attacks detected (threshold: $THRESHOLD attempts)"
else
    echo -e "${RED}[ALERT]${NC} Brute force detected from:"
    for ip in $BRUTE_FORCE_IPS; do
        COUNT=$(grep "Failed password" "$LOG_FILE" | grep -c "$ip")
        echo -e "  ${RED}→ $ip ($COUNT attempts)${NC}"
        echo "  Recommended action: sudo iptables -A INPUT -s $ip -j DROP"
    done
fi

# --- ANALYSIS 5: Successful logins (for audit) ---
echo ""
echo -e "${YELLOW}[5] SUCCESSFUL LOGINS${NC}"
echo "-------------------------------------------"
grep "Accepted" "$LOG_FILE" | awk '{print $9, "from", $11, "at", $1, $2, $3}' || echo "None found"

echo ""
echo "============================================"
echo " Scan complete: $TIMESTAMP"
echo "============================================"
