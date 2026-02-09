#!/bin/bash

###########################################
# Log Monitor - Alternative Version (No Grep Buffering)
# Processes filtering in bash to avoid pipe buffering issues
###########################################

# Configuration - CUSTOMIZE THESE VALUES
WHITELIST_FILE="whitelist.txt"
SEARCH_PATTERN="SEARCH_PATTERN_PLACEHOLDER"  # e.g., "load", "module_load", "bpf_prog_load"
BPF_PROGRAM_NAME_PATTERN='^[^[:space:]]+'  # For BPF: extracts first word in line
AUDIT_PROGRAM_NAME_PATTERN='proctitle="([^"]+)"'  # For Audit: extracts proctitle="title"
BUFFER_SECONDS=5  # Time window for log comparison
TEMP_DIR="/tmp/log_monitor_$$"
BPF_LOG="$TEMP_DIR/bpf.log"
AUDIT_LOG="$TEMP_DIR/audit.log"
BPF_NORMALIZED="$TEMP_DIR/bpf_normalized.log"
AUDIT_NORMALIZED="$TEMP_DIR/audit_normalized.log"

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} This script requires root privileges to read BPF tracepipe and audit logs."
   echo -e "${BLUE}[INFO]${NC} Please run with: sudo bash log_monitor_alt.sh"
   exit 1
fi

# Setup
setup() {
    echo -e "${GREEN}[INFO]${NC} Starting Log Monitor (Alternative - No Grep Buffering)..."
    echo -e "${BLUE}[INFO]${NC} Search pattern: '$SEARCH_PATTERN'"
    echo -e "${BLUE}[INFO]${NC} BPF program name pattern: '$BPF_PROGRAM_NAME_PATTERN'"
    echo -e "${BLUE}[INFO]${NC} Audit program name pattern: '$AUDIT_PROGRAM_NAME_PATTERN'"
    echo -e "${BLUE}[INFO]${NC} Whitelist file: $WHITELIST_FILE"
    echo -e "${BLUE}[INFO]${NC} Buffer seconds: $BUFFER_SECONDS"
    echo ""
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # Create whitelist file if it doesn't exist
    if [[ ! -f "$WHITELIST_FILE" ]]; then
        echo -e "${YELLOW}[WARNING]${NC} Whitelist file $WHITELIST_FILE not found. Creating empty file."
        cat > "$WHITELIST_FILE" << 'EOF'
# Whitelist File
# Add program names here that should NOT trigger alerts, one per line
# Lines starting with # are comments and will be ignored
# Example entries:
# systemd
# dockerd
# containerd
EOF
    fi
    
    # Load whitelist
    load_whitelist
}

# Load whitelist into memory
load_whitelist() {
    if [[ -f "$WHITELIST_FILE" ]]; then
        WHITELIST=$(grep -v '^#' "$WHITELIST_FILE" | grep -v '^[[:space:]]*$')
        local count=$(echo "$WHITELIST" | grep -c .)
        echo -e "${GREEN}[INFO]${NC} Loaded $count whitelisted programs"
    else
        WHITELIST=""
        echo -e "${YELLOW}[WARNING]${NC} No whitelist loaded"
    fi
}

# Extract program name from log line
extract_program_name() {
    local log_line="$1"
    local source="$2"  # "BPF" or "AUDIT"
    
    if [[ "$source" == "BPF" ]]; then
        # For BPF: extract first word in line
        echo "$log_line" | grep -oP "$BPF_PROGRAM_NAME_PATTERN" | head -1
    elif [[ "$source" == "AUDIT" ]]; then
        # For Audit: extract from proctitle="title" format
        echo "$log_line" | grep -oP "$AUDIT_PROGRAM_NAME_PATTERN" | head -1 | sed 's/proctitle="//;s/"//'
    fi
}

# Check if program is whitelisted
is_whitelisted() {
    local log_line="$1"
    local source="$2"  # "BPF" or "AUDIT"
    local program_name=$(extract_program_name "$log_line" "$source")
    
    if [[ -n "$program_name" ]]; then
        while IFS= read -r whitelisted; do
            if [[ "$program_name" == "$whitelisted" ]]; then
                return 0  # Is whitelisted
            fi
        done <<< "$WHITELIST"
    fi
    
    return 1  # Not whitelisted
}

# Alert on load operation
alert_load_operation() {
    local source="$1"
    local log_line="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo ""
    echo "================================================================================"
    echo -e "${RED}[ALERT]${NC} Load operation detected from $source"
    echo -e "${BLUE}[TIME]${NC} $timestamp"
    echo -e "${BLUE}[LOG]${NC} $log_line"
    echo "================================================================================"
    echo ""
}

# Normalize log entry for comparison
normalize_log_entry() {
    local log_line="$1"
    # Remove timestamps and source-specific prefixes
    # Adjust based on your specific log format
    echo "$log_line" | \
        sed 's/[0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}//g' | \
        sed 's/[0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}//g' | \
        sed 's/^[[:space:]]*[^[:space:]]*[[:space:]]*[0-9]*[[:space:]]*//' | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

# Check if line matches pattern (case-insensitive)
matches_pattern() {
    local line="$1"
    local pattern="$2"
    
    # Convert both to lowercase for case-insensitive match
    local line_lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')
    local pattern_lower=$(echo "$pattern" | tr '[:upper:]' '[:lower:]')
    
    [[ "$line_lower" == *"$pattern_lower"* ]]
}

# Monitor BPF tracepipe
monitor_bpf_tracepipe() {
    echo -e "${GREEN}[INFO]${NC} Starting BPF tracepipe monitor..."
    echo -e "${BLUE}[INFO]${NC} Reading directly from trace_pipe (no grep buffering)"
    
    # Read directly from trace_pipe, filter in bash
    while IFS= read -r line; do
        # Check if line matches our search pattern
        if matches_pattern "$line" "$SEARCH_PATTERN"; then
            # Check if whitelisted
            if ! is_whitelisted "$line" "BPF"; then
                # Alert on load operation
                alert_load_operation "BPF" "$line"
            fi
            
            # Store entry with timestamp
            echo "$(date +%s)|$line" >> "$BPF_LOG"
        fi
    done < /sys/kernel/debug/tracing/trace_pipe
}

# Monitor auditd
monitor_auditd() {
    echo -e "${GREEN}[INFO]${NC} Starting auditd monitor..."
    echo -e "${BLUE}[INFO]${NC} Reading directly from audit.log (no grep buffering)"
    
    # Follow audit log, filter in bash
    tail -F /var/log/audit/audit.log 2>/dev/null | while IFS= read -r line; do
        # Check if line matches our search pattern
        if matches_pattern "$line" "$SEARCH_PATTERN"; then
            # Check if whitelisted
            if ! is_whitelisted "$line" "AUDIT"; then
                # Alert on load operation
                alert_load_operation "AUDIT" "$line"
            fi
            
            # Store entry with timestamp
            echo "$(date +%s)|$line" >> "$AUDIT_LOG"
        fi
    done
}

# Compare logs and report discrepancies
compare_logs() {
    echo -e "${GREEN}[INFO]${NC} Starting log comparison thread..."
    
    while true; do
        sleep "$BUFFER_SECONDS"
        
        local current_time=$(date +%s)
        local cutoff_time=$((current_time - (BUFFER_SECONDS * 2)))
        
        # Clear normalized files
        > "$BPF_NORMALIZED"
        > "$AUDIT_NORMALIZED"
        
        # Process BPF entries within time window
        if [[ -f "$BPF_LOG" ]]; then
            while IFS='|' read -r timestamp log_line; do
                if [[ $timestamp -ge $cutoff_time ]]; then
                    normalize_log_entry "$log_line" >> "$BPF_NORMALIZED"
                fi
            done < "$BPF_LOG"
        fi
        
        # Process AUDIT entries within time window
        if [[ -f "$AUDIT_LOG" ]]; then
            while IFS='|' read -r timestamp log_line; do
                if [[ $timestamp -ge $cutoff_time ]]; then
                    normalize_log_entry "$log_line" >> "$AUDIT_NORMALIZED"
                fi
            done < "$AUDIT_LOG"
        fi
        
        # Sort and unique the normalized logs
        if [[ -f "$BPF_NORMALIZED" ]]; then
            sort -u "$BPF_NORMALIZED" > "${BPF_NORMALIZED}.tmp"
            mv "${BPF_NORMALIZED}.tmp" "$BPF_NORMALIZED"
        fi
        
        if [[ -f "$AUDIT_NORMALIZED" ]]; then
            sort -u "$AUDIT_NORMALIZED" > "${AUDIT_NORMALIZED}.tmp"
            mv "${AUDIT_NORMALIZED}.tmp" "$AUDIT_NORMALIZED"
        fi
        
        # Find discrepancies
        if [[ -f "$BPF_NORMALIZED" && -f "$AUDIT_NORMALIZED" ]]; then
            local bpf_only=$(comm -23 "$BPF_NORMALIZED" "$AUDIT_NORMALIZED")
            local audit_only=$(comm -13 "$BPF_NORMALIZED" "$AUDIT_NORMALIZED")
            
            if [[ -n "$bpf_only" ]]; then
                echo ""
                echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                echo -e "${YELLOW}[DISCREPANCY]${NC} Found in BPF but NOT in AUDIT:"
                echo "$bpf_only"
                echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                echo ""
            fi
            
            if [[ -n "$audit_only" ]]; then
                echo ""
                echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                echo -e "${YELLOW}[DISCREPANCY]${NC} Found in AUDIT but NOT in BPF:"
                echo "$audit_only"
                echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
                echo ""
            fi
        fi
        
        # Clean up old entries from log files
        if [[ -f "$BPF_LOG" ]]; then
            grep -E "^[0-9]+\|" "$BPF_LOG" | awk -F'|' -v cutoff="$cutoff_time" '$1 >= cutoff' > "${BPF_LOG}.tmp"
            mv "${BPF_LOG}.tmp" "$BPF_LOG"
        fi
        
        if [[ -f "$AUDIT_LOG" ]]; then
            grep -E "^[0-9]+\|" "$AUDIT_LOG" | awk -F'|' -v cutoff="$cutoff_time" '$1 >= cutoff' > "${AUDIT_LOG}.tmp"
            mv "${AUDIT_LOG}.tmp" "$AUDIT_LOG"
        fi
    done
}

# Cleanup on exit
cleanup() {
    echo ""
    echo -e "${BLUE}[INFO]${NC} Shutting down..."
    
    # Kill all background jobs
    jobs -p | xargs -r kill 2>/dev/null
    
    # Remove temp directory
    rm -rf "$TEMP_DIR"
    
    echo -e "${GREEN}[INFO]${NC} Stopped."
    exit 0
}

# Trap Ctrl+C and cleanup
trap cleanup SIGINT SIGTERM

# Main execution
main() {
    setup
    
    # Start monitoring processes in background
    monitor_bpf_tracepipe &
    monitor_auditd &
    compare_logs &
    
    echo -e "${GREEN}[INFO]${NC} All monitors started. Press Ctrl+C to stop."
    echo -e "${BLUE}[INFO]${NC} This version processes filtering in bash (no grep pipe buffering)"
    echo ""
    
    # Wait for all background processes
    wait
}

# Run main
main
