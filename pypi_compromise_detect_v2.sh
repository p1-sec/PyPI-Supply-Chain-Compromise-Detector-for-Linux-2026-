#!/usr/bin/env bash
# =============================================================================
# PyPI Supply Chain Compromise — Linux Detection Script
# Campaign: Mini Shai-Hulud / TeamPCP (2026)
#
# CONFIRMED COMPROMISED PACKAGES (PyPI):
#   lightning          2.6.2, 2.6.3    — Bun-based credential stealer
#   pytorch-lightning  2.6.2, 2.6.3    — Same payload
#   durabletask        1.4.1–1.4.3     — Credential theft + locale-gated wiper
#   litellm            (Mar 2026)       — .pth file exploit, cred exfiltration
#
# MIRROR NOTE:
#   pypi.tuna.tsinghua.edu.cn is a read-mirror of PyPI.
#   Compromised versions were fully available via this mirror.
#
# LOCALE WARNING:
#   The durabletask wiper SKIPS Russian locale systems only.
#   All other locales (en_IE, en_GB, etc.) are targeted.
#
# USAGE:
#   chmod +x pypi_compromise_detect.sh
#   sudo bash pypi_compromise_detect.sh
#
# Output: /tmp/pypi_compromise_<timestamp>.log
# =============================================================================

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── State ─────────────────────────────────────────────────────────────────────
HITS=0
WARNINGS=0
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="/tmp/pypi_compromise_${TIMESTAMP}.log"
declare -a SITE_PKG_ENTRIES=()   # "python_bin:::site_packages_path"

# ── Logging helpers ───────────────────────────────────────────────────────────
_log()    { echo -e "$1" | tee -a "$REPORT"; }
hit()     { _log "${RED}[CRITICAL]${NC} $1"; HITS=$((HITS + 1)); }
warn()    { _log "${YELLOW}[WARNING] ${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
info()    { _log "${CYAN}[INFO]    ${NC} $1"; }
ok()      { _log "${GREEN}[OK]      ${NC} $1"; }
sub()     { _log "${DIM}           ↳ $1${NC}"; }
section() {
    _log ""
    _log "${BOLD}══════════════════════════════════════════════════════════════${NC}"
    _log "${BOLD}  ▶  $1${NC}"
    _log "${BOLD}══════════════════════════════════════════════════════════════${NC}"
}

# ── Privilege check ───────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${YELLOW}[!] Not running as root. Checks against /etc/, /var/log/,"
    echo -e "    and system-wide cron may be incomplete."
    echo -e "    Re-run with: sudo bash $0${NC}\n"
fi

# ── Report header ─────────────────────────────────────────────────────────────
_log "${BOLD}PyPI Supply Chain Compromise — Detection Report${NC}"
_log "Hostname : $(hostname)"
_log "Date     : $(date)"
_log "User     : $(whoami)"
_log "Locale   : ${LANG:-unset}"
_log "Report   : $REPORT"
_log ""
if [[ "${LANG:-}" != ru_* ]] && [[ "${LC_ALL:-}" != ru_* ]]; then
    _log "${YELLOW}[NOTE] Non-Russian locale detected — durabletask wiper was ACTIVE on this system${NC}"
fi

# =============================================================================
# 1.  PYTHON ENVIRONMENT DISCOVERY
# =============================================================================
section "1. PYTHON ENVIRONMENT DISCOVERY"

_discover_envs() {
    local -a bins=()

    # System Python
    for p in /usr/bin/python3 /usr/bin/python \
              /usr/local/bin/python3 /usr/local/bin/python; do
        [ -x "$p" ] && bins+=("$p")
    done

    # pyenv
    if [ -d "$HOME/.pyenv/versions" ]; then
        while IFS= read -r p; do bins+=("$p"); done < <(
            find "$HOME/.pyenv/versions" -maxdepth 4 \
                \( -name "python3" -o -name "python" \) \
                -path "*/bin/*" 2>/dev/null | head -20
        )
    fi

    # Virtual environments (detect via pyvenv.cfg)
    local search_roots=("/home" "/root" "/opt" "/srv" "/var" "$HOME")
    for root in "${search_roots[@]}"; do
        [ -d "$root" ] || continue
        while IFS= read -r cfg; do
            local venv_dir
            venv_dir=$(dirname "$cfg")
            local p="$venv_dir/bin/python3"
            [ -x "$p" ] || p="$venv_dir/bin/python"
            [ -x "$p" ] && bins+=("$p")
        done < <(find "$root" -maxdepth 7 -name "pyvenv.cfg" 2>/dev/null | head -30)
    done

    # conda environments (detect via conda-meta)
    for root in "/opt/conda" "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/.conda"; do
        [ -d "$root" ] || continue
        while IFS= read -r meta_dir; do
            local env_root
            env_root=$(dirname "$meta_dir")
            local p="$env_root/bin/python3"
            [ -x "$p" ] || p="$env_root/bin/python"
            [ -x "$p" ] && bins+=("$p")
        done < <(find "$root" -maxdepth 5 -name "conda-meta" -type d 2>/dev/null | head -20)
    done

    # Deduplicate and resolve site-packages
    local -A seen=()
    for py_bin in $(printf "%s\n" "${bins[@]}" | sort -u); do
        local site_pkg
        site_pkg=$("$py_bin" -c \
            "import site; print(site.getsitepackages()[0])" 2>/dev/null || true)
        [ -z "$site_pkg" ] && continue
        [ -d "$site_pkg" ] || continue
        local key="${py_bin}:::${site_pkg}"
        if [ -z "${seen[$key]+_}" ]; then
            seen[$key]=1
            SITE_PKG_ENTRIES+=("$key")
            info "Found: $py_bin  →  $site_pkg"
        fi
    done

    if [ ${#SITE_PKG_ENTRIES[@]} -eq 0 ]; then
        warn "No Python environments found."
    fi
}

_discover_envs

# =============================================================================
# 2.  MALICIOUS PACKAGE VERSION CHECK
# =============================================================================
section "2. MALICIOUS PACKAGE VERSION CHECK"

# "pkg_name:bad_version1,bad_version2"
declare -a MALICIOUS_PINNED=(
    "lightning:2.6.2,2.6.3"
    "pytorch-lightning:2.6.2,2.6.3"
    "pytorch_lightning:2.6.2,2.6.3"
    "durabletask:1.4.1,1.4.2,1.4.3"
)

# Packages where we flag presence and advise manual version check
declare -a FLAG_IF_PRESENT=(
    "litellm"
)

for entry in "${SITE_PKG_ENTRIES[@]}"; do
    py_bin="${entry%%:::*}"
    site_pkg="${entry##*:::}"
    _log "\n  Scanning: ${DIM}$site_pkg${NC}"

    for pkg_entry in "${MALICIOUS_PINNED[@]}"; do
        pkg_name="${pkg_entry%%:*}"
        bad_versions="${pkg_entry##*:}"

        installed=$("$py_bin" -m pip show "$pkg_name" 2>/dev/null \
                    | awk '/^Version:/{print $2}' || true)

        [ -z "$installed" ] && continue
        info "Installed: $pkg_name==$installed"

        IFS=',' read -ra bv_arr <<< "$bad_versions"
        for bv in "${bv_arr[@]}"; do
            if [ "$installed" = "$bv" ]; then
                hit "MALICIOUS VERSION CONFIRMED: $pkg_name==$installed in $site_pkg"
            fi
        done
    done

    for pkg_name in "${FLAG_IF_PRESENT[@]}"; do
        installed=$("$py_bin" -m pip show "$pkg_name" 2>/dev/null \
                    | awk '/^Version:/{print $2}' || true)
        if [ -n "$installed" ]; then
            warn "$pkg_name==$installed found — cross-check install date against"
            sub "March 25 2026 compromise window."
            sub "Ref: https://www.truesec.com/hub/blog/malicious-pypi-package-litellm-supply-chain-compromise"
        fi
    done
done

# =============================================================================
# 3.  BUN RUNTIME ARTIFACTS  (lightning / pytorch-lightning attack)
# =============================================================================
section "3. BUN RUNTIME ARTIFACTS  (lightning Bun-based stealer)"
# The payload downloads the Bun JS runtime then executes an ~11 MB obfuscated
# credential stealer. The runtime lands in a hidden _runtime/ directory.

for entry in "${SITE_PKG_ENTRIES[@]}"; do
    site_pkg="${entry##*:::}"
    for pkg_dir in "$site_pkg/lightning" "$site_pkg/pytorch_lightning"; do
        [ -d "$pkg_dir" ] || continue
        if [ -d "$pkg_dir/_runtime" ]; then
            hit "Bun stealer artifact: _runtime/ found in $pkg_dir"
        fi
        if find "$pkg_dir" -name "bun" -type f 2>/dev/null | grep -q .; then
            hit "Bun binary found inside package directory: $pkg_dir"
        fi
    done
done

# Common Bun download drop-zones
for bun_path in /tmp/bun /var/tmp/bun \
                "$HOME/.bun/bin/bun" /root/.bun/bin/bun \
                /tmp/.bun /tmp/.runtime; do
    if [ -f "$bun_path" ]; then
        hit "Bun runtime binary at: $bun_path — lightning stealer artifact"
    fi
done

# pip cache — package may have been uninstalled but payload already ran
declare -a PIP_CACHE_ROOTS=(
    "$HOME/.cache/pip"
    "/root/.cache/pip"
    "/var/cache/pip"
)
declare -a MALICIOUS_CACHE_STEMS=(
    "lightning-2.6.2"    "lightning-2.6.3"
    "pytorch_lightning-2.6.2" "pytorch_lightning-2.6.3"
    "durabletask-1.4.1"  "durabletask-1.4.2"  "durabletask-1.4.3"
)

for cache_root in "${PIP_CACHE_ROOTS[@]}"; do
    [ -d "$cache_root" ] || continue
    for stem in "${MALICIOUS_CACHE_STEMS[@]}"; do
        results=$(find "$cache_root" -iname "${stem}*" 2>/dev/null | head -5)
        if [ -n "$results" ]; then
            hit "Malicious package artifact found in pip cache: $stem"
            sub "Cache: $cache_root"
            sub "⚠  Uninstalling does NOT undo damage — payload runs at install/import time"
            echo "$results" | while IFS= read -r f; do sub "File: $f"; done
        fi
    done
done

# =============================================================================
# 4.  SUSPICIOUS .PTH FILE CHECK  (litellm attack)
# =============================================================================
section "4. SUSPICIOUS .PTH FILES  (litellm .pth exploit)"
# Python executes .pth files in site-packages on interpreter startup.
# Legitimate .pth files only contain plain directory paths.
# Any .pth with import statements or base64/exec is a red flag.

for entry in "${SITE_PKG_ENTRIES[@]}"; do
    site_pkg="${entry##*:::}"
    [ -d "$site_pkg" ] || continue

    while IFS= read -r pth_file; do
        content=$(cat "$pth_file" 2>/dev/null || true)
        if echo "$content" | grep -qE \
            "^import |^exec\(|__import__|base64|\.decode\(|eval\(|subprocess"; then
            hit "Executable code in .pth file: $pth_file"
            echo "$content" | head -5 | while IFS= read -r line; do
                sub "Line: $line"
            done
        fi
    done < <(find "$site_pkg" -maxdepth 2 -name "*.pth" -type f 2>/dev/null)
done

# =============================================================================
# 5.  C2 COMMUNICATION INDICATORS  (durabletask — TeamPCP)
# =============================================================================
section "5. C2 COMMUNICATION INDICATORS  (durabletask — ddjidd564.github.io)"

declare -a C2_IOCS=("ddjidd564.github.io" "ddjidd564")

# /etc/hosts sinkhole check
if [ -f /etc/hosts ]; then
    for ioc in "${C2_IOCS[@]}"; do
        if grep -q "$ioc" /etc/hosts 2>/dev/null; then
            warn "C2 indicator '$ioc' in /etc/hosts (manual triage needed)"
        fi
    done
fi

# System journal (DNS resolutions / network activity)
if command -v journalctl &>/dev/null; then
    for ioc in "${C2_IOCS[@]}"; do
        if journalctl --since "90 days ago" 2>/dev/null | grep -qi "$ioc"; then
            hit "C2 indicator '$ioc' found in system journal"
        fi
    done
fi

# Flat log files
for log_file in /var/log/syslog /var/log/messages \
                /var/log/auth.log /var/log/kern.log; do
    [ -f "$log_file" ] || continue
    for ioc in "${C2_IOCS[@]}"; do
        if grep -qi "$ioc" "$log_file" 2>/dev/null; then
            hit "C2 indicator '$ioc' in $log_file"
        fi
    done
done

# Active outbound connections
_log "\n  Active outbound connections (review for anomalies):"
if command -v ss &>/dev/null; then
    ss -tnp 2>/dev/null | grep -Ev "127\.0\.0\.1|::1|LISTEN" | tee -a "$REPORT" || true
elif command -v netstat &>/dev/null; then
    netstat -tnp 2>/dev/null | grep -Ev "127\.0\.0\.1|::1|LISTEN" | tee -a "$REPORT" || true
fi

# =============================================================================
# 6.  PERSISTENCE MECHANISM DETECTION
# =============================================================================
section "6. PERSISTENCE MECHANISMS"

# ── Shell profiles ────────────────────────────────────────────────────────────
declare -a SHELL_PROFILES=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.bash_login"
    "$HOME/.profile"
    "$HOME/.zshrc"
    "$HOME/.zprofile"
    "$HOME/.config/fish/config.fish"
    /etc/profile
    /etc/bash.bashrc
    /etc/environment
)
if [ -d /etc/profile.d ]; then
    while IFS= read -r f; do SHELL_PROFILES+=("$f"); done < <(
        find /etc/profile.d -name "*.sh" 2>/dev/null
    )
fi

declare -a SUSPICIOUS_PATTERNS=(
    "(curl|wget).*\|.*(bash|sh|python)"
    "base64.*(-d|--decode)"
    "eval[[:space:]]*\\\$\("
    "/dev/tcp/"
    "python[0-9.]* -c.*exec"
    "python[0-9.]* -c.*base64"
    "nc[[:space:]]+-e"
    "ncat.*-e"
)

_log "\n  Checking shell profiles..."
for profile in "${SHELL_PROFILES[@]}"; do
    [ -f "$profile" ] || continue
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if grep -qE "$pattern" "$profile" 2>/dev/null; then
            hit "Suspicious shell hook in: $profile"
            sub "Pattern: $pattern"
            grep -E "$pattern" "$profile" | head -3 | while IFS= read -r line; do
                sub "Line: $line"
            done
            break
        fi
    done
done

# ── Cron ─────────────────────────────────────────────────────────────────────
_log "\n  Checking cron jobs..."
CRON_PATTERN="(curl|wget|python[0-9.]*[[:space:]]+-c|nc[[:space:]]|/dev/tcp|base64)"

# Current user crontab
if crontab -l 2>/dev/null | grep -qE "$CRON_PATTERN"; then
    hit "Suspicious entry in user crontab (run: crontab -l)"
fi

for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly \
                /etc/cron.weekly /var/spool/cron \
                /var/spool/cron/crontabs; do
    [ -d "$cron_dir" ] || continue
    while IFS= read -r cron_file; do
        if grep -qE "$CRON_PATTERN" "$cron_file" 2>/dev/null; then
            hit "Suspicious cron entry in: $cron_file"
            grep -E "$CRON_PATTERN" "$cron_file" | while IFS= read -r line; do
                sub "Entry: $line"
            done
        fi
    done < <(find "$cron_dir" -type f 2>/dev/null)
done

# ── Systemd ───────────────────────────────────────────────────────────────────
_log "\n  Checking systemd units (modified in last 90 days)..."
SYSTEMD_EXEC_PATTERN="(ExecStart|ExecStartPre|ExecStartPost).*=.*(curl|wget|python|bash|nc[[:space:]]|/dev/tcp|base64)"

for systemd_dir in /etc/systemd/system /usr/lib/systemd/system \
                   "$HOME/.config/systemd/user" /root/.config/systemd/user; do
    [ -d "$systemd_dir" ] || continue
    while IFS= read -r svc_file; do
        if grep -qE "$SYSTEMD_EXEC_PATTERN" "$svc_file" 2>/dev/null; then
            hit "Suspicious systemd unit: $svc_file"
            grep -E "$SYSTEMD_EXEC_PATTERN" "$svc_file" | while IFS= read -r line; do
                sub "Exec: $line"
            done
        fi
    done < <(find "$systemd_dir" -name "*.service" -mtime -90 2>/dev/null)
done

# ── Processes running from suspicious locations ───────────────────────────────
_log "\n  Checking running processes for suspicious origins..."
PROC_PATTERN="(/tmp/\.|python.*-c.*base64|curl.*\|.*sh|wget.*\|.*sh)"
if ps aux 2>/dev/null | grep -vE "grep|sshd|systemd" | grep -qE "$PROC_PATTERN"; then
    hit "Suspicious running process detected:"
    ps aux | grep -vE "grep|sshd|systemd" | grep -E "$PROC_PATTERN" | \
        while IFS= read -r line; do sub "$line"; done
fi

# =============================================================================
# 7.  AI ASSISTANT CONFIG FILE POISONING
# =============================================================================
section "7. AI ASSISTANT CONFIG FILE POISONING"
# durabletask payload plants persistence inside .cursorrules and CLAUDE.md
# These files are read and executed by AI coding assistants (Cursor, Claude Code).

declare -a AI_CONFIGS=(
    "$HOME/.cursorrules"
    "$HOME/CLAUDE.md"
    "$HOME/claude.md"
    "$HOME/.claude/CLAUDE.md"
    "/root/.cursorrules"
    "/root/CLAUDE.md"
    "/root/claude.md"
    "$HOME/.config/cursor/.cursorrules"
)

# Scan common project directories
for proj_root in "$HOME/projects" "$HOME/work" "$HOME/dev" \
                 "$HOME/src" "/opt" "/srv" "/var/www"; do
    [ -d "$proj_root" ] || continue
    while IFS= read -r ai_file; do
        AI_CONFIGS+=("$ai_file")
    done < <(find "$proj_root" -maxdepth 5 \
        \( -name ".cursorrules" -o -name "CLAUDE.md" -o -name "claude.md" \) \
        2>/dev/null | head -30)
done

AI_EXEC_PATTERN="(curl|wget).*(http|https)|(base64)|(exec|eval)|(os\.system|subprocess)|(python.*-c)|(\/bin\/(bash|sh))"

for ai_config in $(printf "%s\n" "${AI_CONFIGS[@]}" | sort -u); do
    [ -f "$ai_config" ] || continue
    mod_time=$(stat -c '%y' "$ai_config" 2>/dev/null | cut -d. -f1)
    info "AI config found: $ai_config  (modified: $mod_time)"
    if grep -qE "$AI_EXEC_PATTERN" "$ai_config" 2>/dev/null; then
        hit "Suspicious executable content in AI config: $ai_config"
        grep -E "$AI_EXEC_PATTERN" "$ai_config" | head -5 | while IFS= read -r line; do
            sub "Line: $line"
        done
    fi
done

# =============================================================================
# 8.  CREDENTIAL FILE INTEGRITY
# =============================================================================
section "8. CREDENTIAL FILE INTEGRITY"
# durabletask payload exfiltrates: AWS, Azure, GCP, Kubernetes credentials,
# SSH keys, browser data, and crypto wallet keys.

_check_file() {
    local file="$1" label="$2" warn_days="${3:-60}"
    [ -f "$file" ] || { info "$label not found: $file"; return; }

    local mod_epoch now_epoch age_days
    mod_epoch=$(stat -c %Y "$file" 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    age_days=$(( (now_epoch - mod_epoch) / 86400 ))

    info "$label: $file  (modified ${age_days}d ago)"
    if [ "$age_days" -lt "$warn_days" ]; then
        warn "$label modified within last ${warn_days} days — verify this was authorised"
    fi
}

_check_file "$HOME/.aws/credentials"        "AWS credentials"
_check_file "$HOME/.aws/config"             "AWS config"
_check_file "$HOME/.kube/config"            "kubeconfig"
_check_file "$HOME/.config/gcloud/credentials.db" "GCP credentials"
_check_file "$HOME/.azure/accessTokens.json"       "Azure tokens"
_check_file "$HOME/.ssh/authorized_keys"    "SSH authorized_keys"
_check_file "$HOME/.ssh/id_rsa"             "SSH private key (RSA)"
_check_file "$HOME/.ssh/id_ed25519"         "SSH private key (Ed25519)"
_check_file "/root/.ssh/authorized_keys"    "root SSH authorized_keys"

# Unauthorised SSH public key check
if [ -f "$HOME/.ssh/authorized_keys" ]; then
    key_count=$(grep -cEv "^#|^[[:space:]]*$" "$HOME/.ssh/authorized_keys" 2>/dev/null || echo 0)
    info "SSH authorized_keys entries: $key_count  (verify all are recognised)"
fi

# Exposed secrets in environment
_log "\n  Sensitive env vars present at scan time (may have been exfiltrated):"
env 2>/dev/null \
    | grep -iE "^(AWS_|AZURE_|GOOGLE_|GCP_|GITHUB_TOKEN|GITLAB_TOKEN|\
NPM_TOKEN|PYPI_TOKEN|TWINE_|API_KEY|SECRET|PASSWORD|TOKEN|CREDENTIAL|PRIVATE_KEY)" \
    | sed 's/=.*/=[REDACTED]/' \
    | tee -a "$REPORT" \
    || _log "  (none detected)"

# =============================================================================
# 9.  PIP INSTALL HISTORY & CACHE
# =============================================================================
section "9. PIP INSTALL HISTORY & CACHE"

declare -a PIP_LOG_PATHS=(
    "$HOME/.pip/pip.log"
    "$HOME/.local/state/pip/log/debug.log"
    "/root/.pip/pip.log"
    "/var/log/pip.log"
)

declare -a TARGET_PKGS=(
    "lightning" "pytorch-lightning" "pytorch_lightning"
    "durabletask" "litellm"
)

_log "\n  Campaign install date reference:"
_log "  litellm compromise     : March 25 2026"
_log "  lightning compromise   : April 30 2026"
_log "  Large npm+PyPI campaign: April 29 + May 11 2026"
_log "  durabletask compromise : May 19 2026"
_log "  (Any install of affected packages around these dates = likely compromised)"

for log_path in "${PIP_LOG_PATHS[@]}"; do
    [ -f "$log_path" ] || continue
    info "pip log: $log_path"
    for pkg in "${TARGET_PKGS[@]}"; do
        if grep -qi "$pkg" "$log_path" 2>/dev/null; then
            warn "Install history contains '$pkg' — check timestamp vs campaign dates:"
            grep -i "$pkg" "$log_path" | grep -iE "install|download|collect" | tail -10 | \
                while IFS= read -r line; do sub "$line"; done
        fi
    done
done

# Print full installed package list for manual audit
_log "\n  Full installed packages (for manual review):"
for entry in "${SITE_PKG_ENTRIES[@]}"; do
    py_bin="${entry%%:::*}"
    site_pkg="${entry##*:::}"
    _log "\n  [$site_pkg]"
    "$py_bin" -m pip list 2>/dev/null | tee -a "$REPORT" || true
done

# =============================================================================
# 10. TSINGHUA MIRROR CONFIGURATION AUDIT
# =============================================================================
section "10. TSINGHUA MIRROR CONFIGURATION AUDIT"

TSINGHUA_DOMAIN="pypi.tuna.tsinghua.edu.cn"

declare -a PIP_CONF_PATHS=(
    "$HOME/.pip/pip.conf"
    "$HOME/.config/pip/pip.conf"
    "/etc/pip.conf"
    "/etc/xdg/pip/pip.conf"
)

for pip_conf in "${PIP_CONF_PATHS[@]}"; do
    [ -f "$pip_conf" ] || continue
    info "pip.conf: $pip_conf"
    cat "$pip_conf" | tee -a "$REPORT"
    if grep -q "$TSINGHUA_DOMAIN" "$pip_conf" 2>/dev/null; then
        warn "Tsinghua mirror active in $pip_conf"
        sub "Mirror is a full read-replica of PyPI."
        sub "Compromised versions (lightning 2.6.2/2.6.3, durabletask 1.4.1-1.4.3)"
        sub "were available on this mirror. Version checks above apply equally."
    fi
done

# Check requirements files in common locations
for req_file in "$PWD/requirements.txt" "$PWD/pyproject.toml" \
                "$HOME/requirements.txt" "$HOME/pyproject.toml"; do
    [ -f "$req_file" ] || continue
    info "Requirements file: $req_file"
    for pkg in "${TARGET_PKGS[@]}"; do
        if grep -qi "$pkg" "$req_file" 2>/dev/null; then
            warn "Potentially compromised package '$pkg' referenced in $req_file"
            grep -i "$pkg" "$req_file" | while IFS= read -r line; do sub "$line"; done
        fi
    done
done

# =============================================================================
# SUMMARY & REMEDIATION
# =============================================================================
section "SUMMARY"

_log ""
_log "  Critical hits : ${RED}${BOLD}${HITS}${NC}"
_log "  Warnings      : ${YELLOW}${BOLD}${WARNINGS}${NC}"
_log "  Report saved  : $REPORT"
_log ""

if [ "$HITS" -gt 0 ]; then
    _log "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    _log "${RED}${BOLD}║   ⚠  COMPROMISE INDICATORS FOUND — IMMEDIATE ACTION      ║${NC}"
    _log "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
    _log ""
    _log "${BOLD}Immediate steps:${NC}"
    _log "  1. ISOLATE   — Take this host off the network now"
    _log "  2. ROTATE    — Revoke and regenerate ALL credentials:"
    _log "                   AWS IAM keys (check CloudTrail for misuse)"
    _log "                   Azure service principals & tokens"
    _log "                   GCP service account keys"
    _log "                   Kubernetes service accounts & kubeconfigs"
    _log "                   GitHub / GitLab / PyPI publish tokens"
    _log "                   SSH key pairs (authorised_keys + private keys)"
    _log "                   NPM publish tokens"
    _log "                   Any secrets in environment variables"
    _log "  3. AUDIT     — Review cloud provider access logs for"
    _log "                 unauthorized API calls since install date"
    _log "  4. SWEEP     — Any system sharing credentials with this host"
    _log "                 must also be treated as compromised"
    _log "  5. PRESERVE  — Do not wipe this host before forensic imaging"
    _log "  6. ESCALATE  — Notify your CIRT / security team immediately"
    _log ""
    _log "  C2 infrastructure  : ddjidd564.github.io"
    _log "  Threat actor       : TeamPCP (Mini Shai-Hulud campaign)"
    _log ""

elif [ "$WARNINGS" -gt 0 ]; then
    _log "${YELLOW}${BOLD}No critical IOCs found, but warnings require manual triage.${NC}"
    _log ""
    _log "${BOLD}Recommended actions:${NC}"
    _log "  1. Review every [WARNING] item above"
    _log "  2. Cross-reference pip install timestamps with campaign dates"
    _log "  3. Rotate cloud credentials as a precaution"
    _log "  4. Block C2 at DNS/firewall level: ddjidd564.github.io"
    _log ""

else
    _log "${GREEN}${BOLD}No IOCs detected.${NC}"
    _log ""
    _log "${BOLD}Precautionary hardening:${NC}"
    _log "  1. Block C2 domain at DNS level: ddjidd564.github.io"
    _log "  2. Enable pip hash verification:"
    _log "       pip install --require-hashes -r requirements.txt"
    _log "  3. Pin all production dependencies to exact versions + hashes"
    _log "  4. Feed Sonatype OSS Index / Socket.dev into your MISP instance"
    _log "  5. Add TeamPCP / Mini Shai-Hulud IOCs to your SIEM"
    _log ""
fi

_log "${BOLD}References:${NC}"
_log "  https://www.sonatype.com/blog/malicious-pytorch-lightning-packages-found-on-pypi"
_log "  https://snyk.io/blog/lightning-pypi-compromise-bun-based-credential-stealer/"
_log "  https://www.stepsecurity.io/blog/microsofts-durabletask-pypi-package-compromised-in-supply-chain-attack"
_log "  https://safeguard.sh/resources/blog/durabletask-pypi-compromise-may-2026"
_log "  https://www.truesec.com/hub/blog/malicious-pypi-package-litellm-supply-chain-compromise"
_log "  https://digital.nhs.uk/cyber-alerts/2026/cc-4781"
_log ""
_log "Scan complete: $(date)"
