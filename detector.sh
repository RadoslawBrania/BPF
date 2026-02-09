#!/bin/bash

###########################################
# Log Monitor - Count-Based Comparison
# Counts loads per program and compares between BPF and Audit
###########################################

# Configuration - CUSTOMIZE THESE VALUES
WHITELIST_FILE="whitelist.txt"
SEARCH_PATTERN="SEARCH_PATTERN_PLACEHOLDER"  # e.g., "load", "module_load", "bpf_prog_load"
BPF_PROGRAM_NAME_PATTERN='^[^[:space:]]+'  # For BPF: extracts first word in line
AUDIT_PROGRAM_NAME_PATTERN='proctitle="([^"]+)"'  # For Audit: extracts proctitle="title"
COMPARISON_INTERVAL=10  # How often to compare counts (in seconds)
TEMP_DIR="/tmp/log_monitor_$$"
BPF_COUNTS="$TEMP_DIR/bpf_counts.txt"
AUDIT_COUNTS="$TEMP_DIR/audit_counts.txt"

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} This script requires root privileges to read BPF tracepipe and audit logs."
   echo -e "${BLUE}[INFO]${NC} Please run with: sudo bash log_monitor_counts.sh"
   exit 1
fi

# Setup
setup() {
    echo -e "${GREEN}[INFO]${NC} Starting Log Monitor (Count-Based Comparison)..."
    echo -e "${BLUE}[INFO]${NC} Search pattern: '$SEARCH_PATTERN'"
    echo -e "${BLUE}[INFO]${NC} BPF program name pattern: '$BPF_PROGRAM_NAME_PATTERN'"
    echo -e "${BLUE}[INFO]${NC} Audit program name pattern: '$AUDIT_PROGRAM_NAME_PATTERN'"
    echo -e "${BLUE}[INFO]${NC} Whitelist file: $WHITELIST_FILE"
    echo -e "${BLUE}[INFO]${NC} Comparison interval: ${COMPARISON_INTERVAL}s"
    echo ""
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # Initialize count files
    > "$BPF_COUNTS"
    > "$AUDIT_COUNTS"
    
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
        local count=$(echo "$WHITELIST" | wc -l)
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
    local program_name="$1"
    
    if [[ -n "$program_name" ]]; then
        while IFS= read -r whitelisted; do
            if [[ "$program_name" == "$whitelisted" ]]; then
                return 0  # Is whitelisted
            fi
        done <<< "$WHITELIST"
    fi
    
    return 1  # Not whitelisted
}

# Increment count for a program
increment_count() {
    local program_name="$1"
    local count_file="$2"
    local source="$3"
    
    # Use a lock file to prevent race conditions
    local lock_file="${count_file}.lock"
    
    # Acquire lock
    while ! mkdir "$lock_file" 2>/dev/null; do
        sleep 0.001
    done
    
    # Read current count
    local current_count=0
    if grep -q "^${program_name}=" "$count_file" 2>/dev/null; then
        current_count=$(grep "^${program_name}=" "$count_file" | cut -d'=' -f2)
    fi
    
    # Increment
    local new_count=$((current_count + 1))
    
    # Update file (remove old entry and add new one)
    grep -v "^${program_name}=" "$count_file" 2>/dev/null > "${count_file}.tmp" || true
    echo "${program_name}=${new_count}" >> "${count_file}.tmp"
    mv "${count_file}.tmp" "$count_file"
    
    # Release lock
    rmdir "$lock_file"
}

# Alert on load operation
alert_load_operation() {
    local source="$1"
    local program_name="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    echo -e "${CYAN}[LOAD]${NC} $timestamp - $source - Program: $program_name"
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
    
    # Read directly from trace_pipe, filter in bash
    while IFS= read -r line; do
        # Check if line matches our search pattern
        if matches_pattern "$line" "$SEARCH_PATTERN"; then
            # Extract program name
            local program_name=$(extract_program_name "$line" "BPF")
            
            if [[ -n "$program_name" ]]; then
                # Check if whitelisted
                if ! is_whitelisted "$program_name"; then
                    # Alert on load operation
                    alert_load_operation "BPF" "$program_name"
                fi
                
                # Increment count
                increment_count "$program_name" "$BPF_COUNTS" "BPF"
            fi
        fi
    done < /sys/kernel/debug/tracing/trace_pipe
}

# Monitor auditd
monitor_auditd() {
    echo -e "${GREEN}[INFO]${NC} Starting auditd monitor..."
    
    # Follow audit log, filter in bash
    tail -F /var/log/audit/audit.log 2>/dev/null | while IFS= read -r line; do
        # Check if line matches our search pattern
        if matches_pattern "$line" "$SEARCH_PATTERN"; then
            # Extract program name
            local program_name=$(extract_program_name "$line" "AUDIT")
            
            if [[ -n "$program_name" ]]; then
                # Check if whitelisted
                if ! is_whitelisted "$program_name"; then
                    # Alert on load operation
                    alert_load_operation "AUDIT" "$program_name"
                fi
                
                # Increment count
                increment_count "$program_name" "$AUDIT_COUNTS" "AUDIT"
            fi
        fi
    done
}

# Compare counts and report discrepancies
compare_counts() {
    echo -e "${GREEN}[INFO]${NC} Starting count comparison thread..."
    
    while true; do
        sleep "$COMPARISON_INTERVAL"
        
        echo ""
        echo "================================================================================"
        echo -e "${YELLOW}[COMPARISON]${NC} Load count comparison ($(date '+%Y-%m-%d %H:%M:%S'))"
        echo "================================================================================"
        
        # Get all unique program names from both files
        local all_programs=$(cat "$BPF_COUNTS" "$AUDIT_COUNTS" 2>/dev/null | cut -d'=' -f1 | sort -u)
        
        if [[ -z "$all_programs" ]]; then
            echo "No loads detected yet."
            echo "================================================================================"
            echo ""
            continue
        fi
        
        # Track if we found any discrepancies
        local found_discrepancy=0
        
        # Compare counts for each program
        while IFS= read -r program; do
            # Get counts from each source
            local bpf_count=0
            local audit_count=0
            
            if grep -q "^${program}=" "$BPF_COUNTS" 2>/dev/null; then
                bpf_count=$(grep "^${program}=" "$BPF_COUNTS" | cut -d'=' -f2)
            fi
            
            if grep -q "^${program}=" "$AUDIT_COUNTS" 2>/dev/null; then
                audit_count=$(grep "^${program}=" "$AUDIT_COUNTS" | cut -d'=' -f2)
            fi
            
            # Calculate difference
            local diff=$((bpf_count - audit_count))
            
            # Report if there's a discrepancy
            if [[ $diff -ne 0 ]]; then
                found_discrepancy=1
                if [[ $diff -gt 0 ]]; then
                    echo -e "${RED}[DISCREPANCY]${NC} ${program}:"
                    echo "    BPF: $bpf_count loads"
                    echo "    AUDIT: $audit_count loads"
                    echo "    → BPF has $diff MORE loads than AUDIT"
                else
                    local abs_diff=$((-diff))
                    echo -e "${RED}[DISCREPANCY]${NC} ${program}:"
                    echo "    BPF: $bpf_count loads"
                    echo "    AUDIT: $audit_count loads"
                    echo "    → AUDIT has $abs_diff MORE loads than BPF"
                fi
                echo ""
            else
                # Matching counts
                echo -e "${GREEN}[MATCH]${NC} ${program}: BPF=$bpf_count, AUDIT=$audit_count ✓"
            fi
        done <<< "$all_programs"
        
        if [[ $found_discrepancy -eq 0 ]]; then
            echo -e "${GREEN}All programs have matching load counts!${NC}"
        fi
        
        echo "================================================================================"
        echo ""
    done
}

# Display summary statistics
display_stats() {
    echo -e "${GREEN}[INFO]${NC} Starting statistics display thread..."
    
    while true; do
        sleep 30  # Display stats every 30 seconds
        
        local total_bpf=0
        local total_audit=0
        
        # Sum up all BPF counts
        while IFS='=' read -r prog count; do
            total_bpf=$((total_bpf + count))
        done < "$BPF_COUNTS" 2>/dev/null
        
        # Sum up all AUDIT counts
        while IFS='=' read -r prog count; do
            total_audit=$((total_audit + count))
        done < "$AUDIT_COUNTS" 2>/dev/null
        
        echo -e "${BLUE}[STATS]${NC} Total loads: BPF=$total_bpf, AUDIT=$total_audit ($(date '+%H:%M:%S'))"
    done
}

# Cleanup on exit
cleanup() {
    echo ""
    echo -e "${BLUE}[INFO]${NC} Shutting down..."
    
    # Display final counts
    echo ""
    echo "================================================================================"
    echo -e "${YELLOW}[FINAL COUNTS]${NC}"
    echo "================================================================================"
    
    echo ""
    echo "BPF Load Counts:"
    if [[ -s "$BPF_COUNTS" ]]; then
        sort -t'=' -k2 -nr "$BPF_COUNTS" | while IFS='=' read -r prog count; do
            echo "  $prog: $count"
        done
    else
        echo "  (none)"
    fi
    
    echo ""
    echo "AUDIT Load Counts:"
    if [[ -s "$AUDIT_COUNTS" ]]; then
        sort -t'=' -k2 -nr "$AUDIT_COUNTS" | while IFS='=' read -r prog count; do
            echo "  $prog: $count"
        done
    else
        echo "  (none)"
    fi
    
    echo "================================================================================"
    echo ""
    
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
    compare_counts &
    display_stats &
    
    echo -e "${GREEN}[INFO]${NC} All monitors started. Press Ctrl+C to stop."
    echo -e "${BLUE}[INFO]${NC} This version counts loads per program and compares counts"
    echo -e "${BLUE}[INFO]${NC} Comparisons will run every ${COMPARISON_INTERVAL} seconds"
    echo ""
    
    # Wait for all background processes
    wait
}

# Run main
main
