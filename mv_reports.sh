#!/usr/bin/env bash

SOURCE_DIR="$1"
DEST_DIR="$2"
DRY_RUN="$3"
LOG_FILE="$4"

if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    echo "Usage: $0 <source_directory> <destination_directory> [--dry-run]"
    echo "Moves .xlsx files from source to destination. Use --dry-run to log only."
    exit 0
fi

if [ -z "$SOURCE_DIR" ] || [ -z "$DEST_DIR" ]; then
    echo "Usage: $0 <source_directory> <destination_directory> [--dry-run]"
    exit 1
fi

# Validate directories exist and are accessible
if [ ! -d "$SOURCE_DIR" ] || [ ! -r "$SOURCE_DIR" ]; then
    echo "Error: Source directory does not exist or is not readable: $SOURCE_DIR"
    exit 1
fi

# Ensure destination directory exists
if [ ! -d "$DEST_DIR" ]; then
    echo "Creating destination directory: $DEST_DIR"
    mkdir -p "$DEST_DIR" || { echo "Failed to create destination directory"; exit 1; }
fi

# Ensure log file is writable
touch "$LOG_FILE" 2>/dev/null || { echo "Error: Cannot write to log file: $LOG_FILE"; exit 1; }

# Execute rsync and log output
if [ "$DRY_RUN" = "--dry-run" ]; then
    echo "$(date): DRYRUN mode enabled" | tee -a "$LOG_FILE"
    rsync -avu --include='*.xlsx' --include='*/' --exclude='*' --dry-run "$SOURCE_DIR/" "$DEST_DIR/" 2>&1 | sed 's/^/'"$(date): "'/g' | tee -a "$LOG_FILE"
else
    echo "$(date): Starting transfer of .xlsx files from $SOURCE_DIR to $DEST_DIR" | tee -a "$LOG_FILE"
    rsync -avu --include='*.xlsx' --include='*/' --exclude='*' "$SOURCE_DIR/" "$DEST_DIR/" 2>&1 | sed 's/^/'"$(date): "'/g' | tee -a "$LOG_FILE"
fi

# Check if rsync was successful
if [ "${PIPESTATUS[0]}" -eq 0 ]; then
    echo "$(date): Transfer completed successfully" | tee -a "$LOG_FILE"
else
    echo "$(date): Transfer failed with error code ${PIPESTATUS[0]}" | tee -a "$LOG_FILE"
    exit 1
fi
