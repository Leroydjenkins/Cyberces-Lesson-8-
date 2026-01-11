#!/bin/bash

################################################################################
# Lesson 8 homewokr CIS Security Audit Script for Kali Linux
# Purpose: Check 5 essential security rules on Kali Linux from homework CIS
# Author: Viktorov V. 
# Date: 11.01.2026
################################################################################
#!/bin/bash

Color codes for better readability in terminal output with anci code of colors
GREEN='\033[0;32m'   # Green color for PASS
RED='\033[0;31m'     # Red color for FAIL
YELLOW='\033[1;33m'  # Yellow color for WARNING
BLUE='\033[0;34m'    # Blue color for INFO
NC='\033[0m'         # No Color - resets color to default


# Function to print section headers
print_header() {
    echo ""
    echo "=========================================="
    echo "$1"  # $1 means the first argument passed to the function
    echo "=========================================="
}

# Function to print results with colors for ex Parameters: $1 = status (PASS/FAIL/WARNING/INFO), $2 = message
print_result() {
    if [ "$1" = "PASS" ]; then
        echo -e "${GREEN}[✓] PASS:${NC} $2"
    elif [ "$1" = "FAIL" ]; then
        echo -e "${RED}[✗] FAIL:${NC} $2"
    elif [ "$1" = "INFO" ]; then
        echo -e "${BLUE}[i] INFO:${NC} $2"
    else
        echo -e "${YELLOW}[!] WARNING:${NC} $2"
    fi
}

# Check root rights start
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}Warning: Some checks require root privileges.${NC}"
    echo "Please run with: sudo $0"
    echo ""
fi

print_header "Kali Security check"
print_result "INFO" "Kali version: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"

################################################################################
# 1. Парольна політика (мінімальна довжина пароля >= 8); 
################################################################################
print_header "Парольна політика (мінімальна довжина пароля >= 8)"


MIN_PASS_LENGTH=0

# Check /etc/security/pwquality.conf 
if [ -f /etc/security/pwquality.conf ]; then
    # Looking minlen
    # grep -v "^#" excludes commented lines
    # grep -v "^$" excludes empty lines
    MINLEN=$(grep -E "^minlen" /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' ' || true)
    
    if [ ! -z "$MINLEN" ]; then
        MIN_PASS_LENGTH=$MINLEN
        echo "Found in /etc/security/pwquality.conf: minlen = $MIN_PASS_LENGTH"
    else
        echo "No minlen setting found in pwquality.conf"
    fi
fi

# Checking /etc/pam.d/common-password for pam_pwquality settings
if [ -f /etc/pam.d/common-password ]; then
    # Look for minlen in PAM configuration
    PAM_MINLEN=$(grep "pam_pwquality.so" /etc/pam.d/common-password | grep -oP "minlen=\K[0-9]+" || true)
    
    if [ ! -z "$PAM_MINLEN" ]; then
        MIN_PASS_LENGTH=$PAM_MINLEN
        echo "Found in /etc/pam.d/common-password: minlen = $MIN_PASS_LENGTH"
    fi
fi


# Results
if [ ! -z "$MIN_PASS_LENGTH" ] && [ "$MIN_PASS_LENGTH" -ge 8 ]; then
    print_result "PASS" "Minimum password length is $MIN_PASS_LENGTH (>= 8)"
elif [ ! -z "$MIN_PASS_LENGTH" ]; then
    print_result "FAIL" "Minimum password length is $MIN_PASS_LENGTH (should be >= 8)"
else
    print_result "WARNING" "No password length policy found (using system defaults)"
fi

################################################################################
# 2. Включений фаервол (ufw активний?); 
################################################################################
print_header "Rule 2: CВключений фаервол (ufw активний?)"

# Kali Linux comes with ufw pre-installed but often disabled by default and check if ufw command exists
if command -v ufw >/dev/null 2>&1; then
    print_result "INFO" "UFW is installed on this system"
    
    # Check UFW status
    if [ "$EUID" -eq 0 ]; then
        UFW_STATUS=$(ufw status 2>/dev/null | grep -i "Status:" | awk '{print $2}' || echo "unknown")
    else
        UFW_STATUS=$(sudo ufw status 2>/dev/null | grep -i "Status:" | awk '{print $2}' || echo "unknown")
    fi
    
    echo "UFW Status: $UFW_STATUS"
    
    # Check status "active"
    if [[ "$UFW_STATUS" =~ ^[Aa]ctive$ ]]; then
        print_result "PASS" "UFW firewall is active"
        
        # Additional info for rules 
        if [ "$EUID" -eq 0 ]; then
            RULE_COUNT=$(ufw status numbered 2>/dev/null | grep -c "\[" || echo "0")
        else
            RULE_COUNT=$(sudo ufw status numbered 2>/dev/null | grep -c "\[" || echo "0")
        fi
        echo "Number of firewall rules configured: $RULE_COUNT"
    else
        print_result "FAIL" "UFW firewall is NOT active"
        echo "Note: Kali Linux disables UFW by default. Enable it with: sudo ufw enable"
    fi
else
    print_result "WARNING" "UFW is not installed "
fi

################################################################################
# 3. Відсутність рутового входу через SSH; 
################################################################################
print_header "Rule 3: Відсутність рутового входу через SSH"

# SSH configuration is in /etc/ssh/sshd_config
SSH_CONFIG="/etc/ssh/sshd_config"

# Check if SSH is installed
if ! command -v sshd >/dev/null 2>&1; then
    print_result "INFO" "SSH server is not installed"
    echo "Install with: sudo apt install openssh-server"
else
    print_result "INFO" "SSH server is installed"
    
    if [ -f "$SSH_CONFIG" ]; then
        # Looking for PermitRootLogin
        # ^[^#] means: line starts with any character except # its excluded commented lines

        ROOT_LOGIN=$(grep -E "^[^#]*PermitRootLogin" "$SSH_CONFIG" | tail -1 | awk '{print $2}' || true)
        
        if [ -z "$ROOT_LOGIN" ]; then
            echo "PermitRootLogin: not explicitly set (checking default)"
            # In new versions of SSH, default is often 'prohibit-password'
            ROOT_LOGIN="default"
        else
            echo "PermitRootLogin setting: $ROOT_LOGIN"
        fi
        
        # Best practice: should be "no" or "prohibit-password" but in Kali default is often "yes" which is INSECURE for production but we only study now) 
        if [[ "$ROOT_LOGIN" == "no" ]]; then
            print_result "PASS" "SSH root login is completely disabled (most secure)"
        elif [[ "$ROOT_LOGIN" == "prohibit-password" ]] || [[ "$ROOT_LOGIN" == "without-password" ]]; then
            print_result "PASS" "SSH root login is restricted to key-based auth only"
        elif [[ "$ROOT_LOGIN" == "yes" ]]; then
            print_result "FAIL" "SSH root login with password is ALLOWED (very insecure!)"
            echo "Fix: Change 'PermitRootLogin' to 'no' or 'prohibit-password' in $SSH_CONFIG"
        else
            print_result "WARNING" "PermitRootLogin not explicitly configured"
        fi
        
        # Check if SHH is running
        if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
            echo "SSH service status: RUNNING"
        else
            echo "SSH service status: STOPPED"
        fi
    else
        print_result "WARNING" "SSH config file not found at $SSH_CONFIG"
    fi
fi

################################################################################
# 4. Наявність автоматичних оновлень; 
################################################################################
print_header "Rule 4: Наявність автоматичних оновлень"

# Kali Linux is Debian-based, so it uses unattended-upgrades BUT, Kali typically does NOT enable automatic updates by default because updates can break pentesting tools) 


AUTO_UPDATE_ENABLED=false

# Check installed  unattended-upgrades package
if ! dpkg -l | grep -q "^ii.*unattended-upgrades"; then
    print_result "INFO" "unattended-upgrades package is NOT installed"
    echo "Install with: sudo apt install unattended-upgrades"
else
    print_result "INFO" "unattended-upgrades package is installed"
    
    # Check config files 
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        # Check autoupdates (must be "1")
        UPDATE_ENABLED=$(grep -E "APT::Periodic::Update-Package-Lists" /etc/apt/apt.conf.d/20auto-upgrades | grep -o "[0-9]" || echo "0")
        UPGRADE_ENABLED=$(grep -E "APT::Periodic::Unattended-Upgrade" /etc/apt/apt.conf.d/20auto-upgrades | grep -o "[0-9]" || echo "0")
        
        echo "Update-Package-Lists: $UPDATE_ENABLED (1=enabled, 0=disabled)"
        echo "Unattended-Upgrade: $UPGRADE_ENABLED (1=enabled, 0=disabled)"
        
        if [ "$UPDATE_ENABLED" = "1" ] && [ "$UPGRADE_ENABLED" = "1" ]; then
            AUTO_UPDATE_ENABLED=true
        fi
    fi
    
    # Also check if service is running
    if systemctl is-enabled unattended-upgrades.service >/dev/null 2>&1; then
        echo "unattended-upgrades.service: enabled"
        AUTO_UPDATE_ENABLED=true
    else
        echo "unattended-upgrades.service: disabled or not found"
    fi
fi

# Showing results
if [ "$AUTO_UPDATE_ENABLED" = true ]; then
    print_result "PASS" "Automatic updates are enabled"
else
    print_result "WARNING" "Automatic updates are NOT enabled"
    echo "Note: Kali disables auto-updates by default to prevent tool breakage"
    echo "For a production system, enable with: sudo dpkg-reconfigure -plow unattended-upgrades"
fi

################################################################################
# 5. Налаштована політика блокування облікового запису після N невдалих спроб тощо. 
################################################################################
print_header "5. Налаштована політика блокування облікового запису після N невдалих спроб тощо."

# Kali use PAM (Pluggable Authentication Modules) вместе с faillock configs in /etc/pam.d/ and /etc/security/faillock.conf

FAILLOCK_FOUND=false
MAX_ATTEMPTS=""
UNLOCK_TIME=""

# Check aveilability of faillock
if ! command -v faillock >/dev/null 2>&1; then
    print_result "WARNING" "faillock command not found (libpam-modules might not be installed)"
else
    print_result "INFO" "faillock is available"
    
    # Check /etc/security/faillock.conf (basic config in new systems)
    if [ -f /etc/security/faillock.conf ]; then
        # Search deny
        MAX_ATTEMPTS=$(grep -E "^deny" /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ' || true)
        # Search unlock_time (seconds to auto-unlock)
        UNLOCK_TIME=$(grep -E "^unlock_time" /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ' || true)
        
        if [ ! -z "$MAX_ATTEMPTS" ]; then
            FAILLOCK_FOUND=true
            echo "Found configuration in /etc/security/faillock.conf"
            echo "  deny (max attempts): $MAX_ATTEMPTS"
            [ ! -z "$UNLOCK_TIME" ] && echo "  unlock_time: $UNLOCK_TIME seconds"
        fi
    fi
    
    # Check PAM configs
    for pam_file in /etc/pam.d/common-auth /etc/pam.d/system-auth; do
        if [ -f "$pam_file" ]; then
            # Chehck pam_faillock configs if setuped 
            if grep -q "pam_faillock" "$pam_file"; then
                echo "Found pam_faillock in $pam_file"
                
                # Execude deny, if not finded early
                if [ -z "$MAX_ATTEMPTS" ]; then
                    MAX_ATTEMPTS=$(grep "pam_faillock" "$pam_file" | grep -oP "deny=\K[0-9]+" | head -1 || true)
                fi
                
                # Exedude unlock_time, if not finded early
                if [ -z "$UNLOCK_TIME" ]; then
                    UNLOCK_TIME=$(grep "pam_faillock" "$pam_file" | grep -oP "unlock_time=\K[0-9]+" | head -1 || true)
                fi
                
                FAILLOCK_FOUND=true
            fi
        fi
    done
fi

# Evaluation and result output
if [ "$FAILLOCK_FOUND" = true ]; then
    if [ ! -z "$MAX_ATTEMPTS" ]; then
        # ok for  3–5 try
        if [ "$MAX_ATTEMPTS" -le 5 ]; then
            print_result "PASS" "Failed login blocking configured (max $MAX_ATTEMPTS attempts)"
        elif [ "$MAX_ATTEMPTS" -le 10 ]; then
            print_result "WARNING" "Failed login limit is moderate ($MAX_ATTEMPTS attempts)"
        else
            print_result "WARNING" "Failed login limit is high ($MAX_ATTEMPTS attempts)"
        fi
    else
        print_result "WARNING" "pam_faillock found but deny value not configured"
    fi
else
    print_result "FAIL" "No failed login blocking policy found"
    echo "Recommendation: Configure pam_faillock in /etc/pam.d/common-auth"
    echo "Example: Add these lines to /etc/pam.d/common-auth:"
    echo "  auth required pam_faillock.so preauth deny=5 unlock_time=900"
    echo "  auth required pam_faillock.so authfail deny=5 unlock_time=900"
fi

################################################################################
# Test evaluation and result output for whole test btw just summary 
################################################################################
print_header "Security Audit Complete"
echo -e "${BLUE}Summary:${NC}"
echo "• Password Policy: Check settings in /etc/security/pwquality.conf"
echo "• Firewall: Kali disables UFW by default - enable for production use"
echo "• SSH: Configure /etc/ssh/sshd_config for secure remote access"
echo "• Auto-Updates: Kali disables by default - consider for production systems"
echo "• Login Attempts: Configure PAM faillock to prevent brute-force attacks"
echo ""
echo -e "${YELLOW}Note:${NC} Kali Linux defaults are optimized for pentesting, not production."
echo "For a hardened system, enable all security features above."
echo ""

#Exit with success code
exit 0
