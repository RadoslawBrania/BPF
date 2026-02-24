#!/bin/bash

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

echo "=== Hidden Module Checker ==="
echo ""

# Verify CONFIG_KALLSYMS is enabled
config_file="/boot/config-$(uname -r)"
if [ -f "$config_file" ]; then
    if grep -q "^CONFIG_KALLSYMS=y" "$config_file"; then
        echo -e "${GREEN}[OK]${NC} CONFIG_KALLSYMS=y — sections/ check is reliable"
    else
        echo -e "${YELLOW}[WARN]${NC} CONFIG_KALLSYMS is not enabled — sections/ dirs may be absent even for loaded modules"
        echo "       Results may be unreliable. Proceeding anyway..."
    fi
else
    echo -e "${YELLOW}[WARN]${NC} Could not find kernel config at $config_file — unable to verify CONFIG_KALLSYMS"
fi

echo ""

# Build lsmod list once for efficiency
lsmod_list=$(lsmod | awk 'NR>1 {print $1}')

suspicious=()

for mod_path in /sys/module/*/; do
    name=$(basename "$mod_path")

    # Only consider modules that have a sections/ dir (i.e. dynamically loaded)
    if [ ! -d "${mod_path}sections" ]; then
        continue
    fi

    # Check if it appears in lsmod
    if ! echo "$lsmod_list" | grep -q "^${name}$"; then
        suspicious+=("$name")
    fi
done

# Report
if [ ${#suspicious[@]} -eq 0 ]; then
    echo -e "${GREEN}No suspicious modules found.${NC}"
    echo "All modules with a sections/ directory are accounted for in lsmod."
else
    echo -e "${RED}Suspicious modules found (in /sys/module with sections/ but missing from lsmod):${NC}"
    echo ""
    for name in "${suspicious[@]}"; do
        echo -e "  ${RED}!${NC} $name"
        # Print any additional info available
        if [ -f "/sys/module/${name}/refcnt" ]; then
            refcnt=$(cat "/sys/module/${name}/refcnt" 2>/dev/null)
            echo "      refcnt: $refcnt"
        fi
        if [ -d "/sys/module/${name}/sections" ]; then
            sections=$(ls "/sys/module/${name}/sections/" 2>/dev/null | tr '\n' ' ')
            echo "      sections: $sections"
        fi
    done
fi
