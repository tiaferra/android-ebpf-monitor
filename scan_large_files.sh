#!/bin/bash

# Directory da analizzare (default: directory corrente)
DIR="${1:-.}"

# Soglia in MB
THRESHOLD_MB=50

# Conversione in byte
THRESHOLD_BYTES=$((THRESHOLD_MB * 1024 * 1024))

echo "Scanning directory: $DIR"
echo "Threshold: ${THRESHOLD_MB} MB"
echo "-----------------------------------"

find "$DIR" -type f -print0 | while IFS= read -r -d '' file; do
    size=$(stat -c%s "$file" 2>/dev/null)
    
    if [[ "$size" -gt "$THRESHOLD_BYTES" ]]; then
        size_mb=$(awk "BEGIN {printf \"%.2f\", $size/1024/1024}")
        echo "$file  -->  ${size_mb} MB"
    fi
done
