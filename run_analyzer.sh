#!/bin/bash

CAPTURE_DIR="/captures"
LOG_DIR="/logs"
PROCESSED_DIR="/processed"

echo "[INFO] Starting analyzer. Watching $CAPTURE_DIR for new PCAP files..."

mkdir -p "$CAPTURE_DIR" "$LOG_DIR" "$PROCESSED_DIR"

inotifywait -m -e close_write "$CAPTURE_DIR" |
while read path action file; do
    if [[ "$file" == *.pcap ]]; then
        INPUT_FILE="$CAPTURE_DIR/$file"

        echo "[INFO] Detected new file: $file"

        # Run analyzer and write results with timestamps
        python /app/syn_scan_detector.py "$INPUT_FILE" >> "$LOG_DIR/results.log"

        echo "[INFO] Moving $file to processed folder"
        mv "$INPUT_FILE" "$PROCESSED_DIR/"
    fi
done
