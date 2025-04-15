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

for file in "$SOURCE_DIR"/*.xlsx; do
    if [ -e "$file" ]; then
        basefile=$(basename "$file")
        if [ -e "$DEST_DIR/$basefile" ]; then
            if [ "$DRY_RUN" = "--dry-run" ]; then
                echo "$(date): DRYRUN: $basefile already exists in $DEST_DIR. Not moved."
                echo "$(date): DRYRUN: $basefile already exists in $DEST_DIR. Not moved." >> "$LOG_FILE"
            else
                echo "$(date): $basefile already exists in $DEST_DIR. Not moved."
                echo "$(date): $basefile already exists in $DEST_DIR. Not moved." >> "$LOG_FILE"
            fi
        else
            if [ "$DRY_RUN" = "--dry-run" ]; then
                echo "$(date): DRYRUN: Would move $basefile to $DEST_DIR."
                echo "$(date): DRYRUN: Would move $basefile to $DEST_DIR." >> "$LOG_FILE"
            else
                mv "$file" "$DEST_DIR"/
                echo "$(date): Moved $basefile to $DEST_DIR."
                echo "$(date): Moved $basefile to $DEST_DIR." >> "$LOG_FILE"
            fi
        fi
    fi
done
