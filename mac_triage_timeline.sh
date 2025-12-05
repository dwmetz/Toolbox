#!/bin/bash

# ============================================================================
#  Mac-Triage Timeline Generator v1.0
#  Author: Doug Metz | Baker Street Forensics
#  https://bakerstreetforensics.com
# ============================================================================

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to display banner
display_banner() {
    echo -e "${CYAN}"
    echo "============================================================================"
    echo " Mac-Triage Timeline Generator v1.0"
    echo " Author: Doug Metz | Baker Street Forensics"
    echo " https://bakerstreetforensics.com"
    echo "============================================================================"
    echo -e "${NC}"
}

# Function to print colored messages
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Function to display usage
usage() {
    echo "Usage: $0 -z <mac-triage-zip-file> -c <case-name> [-d <cases-directory>] [-s <start-date>]"
    echo ""
    echo "Options:"
    echo "  -z    Path to Mac-Triage ZIP file (required)"
    echo "  -c    Case name for the new case directory (required)"
    echo "  -d    Base directory for cases (default: ~/cases)"
    echo "  -s    Start date for timeline filter (format: YYYY-MM-DD)"
    echo "  -h    Display this help message"
    echo ""
    echo "Example:"
    echo "  $0 -z /path/to/macos-triage.zip -c suspect_laptop_2024"
    echo "  $0 -z /path/to/macos-triage.zip -c suspect_laptop_2024 -s 2024-01-01"
    exit 1
}

# Default values
CASES_BASE_DIR="$HOME/cases"
ZIP_FILE=""
CASE_NAME=""
START_DATE=""

# Parse command line arguments
while getopts "z:c:d:s:h" opt; do
    case $opt in
        z)
            ZIP_FILE="$OPTARG"
            ;;
        c)
            CASE_NAME="$OPTARG"
            ;;
        d)
            CASES_BASE_DIR="$OPTARG"
            ;;
        s)
            START_DATE="$OPTARG"
            ;;
        h)
            usage
            ;;
        \?)
            print_error "Invalid option: -$OPTARG"
            usage
            ;;
    esac
done

# Validate required arguments
if [ -z "$ZIP_FILE" ] || [ -z "$CASE_NAME" ]; then
    print_error "Missing required arguments"
    usage
fi

# Display banner
display_banner

# Validate ZIP file exists
if [ ! -f "$ZIP_FILE" ]; then
    print_error "ZIP file not found: $ZIP_FILE"
    exit 1
fi

# Check if log2timeline.py is available
if ! command -v log2timeline.py &> /dev/null; then
    print_error "log2timeline.py not found. Please install Plaso first."
    exit 1
fi

# Check if psort.py is available
if ! command -v psort.py &> /dev/null; then
    print_error "psort.py not found. Please install Plaso first."
    exit 1
fi

# Create case directory structure
CASE_DIR="$CASES_BASE_DIR/$CASE_NAME"
EXTRACTED_DIR="$CASE_DIR/extracted"

print_info "Creating case directory: $CASE_DIR"
mkdir -p "$CASE_DIR"
mkdir -p "$EXTRACTED_DIR"

# Extract ZIP file
print_info "Extracting Mac-Triage collection..."
unzip -q "$ZIP_FILE" -d "$EXTRACTED_DIR"

if [ $? -ne 0 ]; then
    print_error "Failed to extract ZIP file"
    exit 1
fi

print_info "Extraction complete"

# Find the Mac-Triage folder (should contain macos-Triage directory)
# Look for the macos-Triage directory within extracted folder
TRIAGE_PATH=$(find "$EXTRACTED_DIR" -type d -name "macos-Triage" | head -n 1)

if [ -z "$TRIAGE_PATH" ]; then
    print_error "Could not find macos-Triage directory in extracted files"
    print_info "Contents of extracted directory:"
    ls -la "$EXTRACTED_DIR"
    exit 1
fi

print_info "Found triage data at: $TRIAGE_PATH"

# Run log2timeline
PLASO_FILE="$CASE_DIR/macos.plaso"
print_info "Running log2timeline (this may take a while)..."
print_info "Output file: $PLASO_FILE"

log2timeline.py \
  --storage-file "$PLASO_FILE" \
  --parsers macos \
  --hashers none \
  "$TRIAGE_PATH"

if [ $? -ne 0 ]; then
    print_error "log2timeline.py failed"
    exit 1
fi

print_info "log2timeline processing complete"

# Run psort to create timeline
CSV_OUTPUT="$CASE_DIR/macos_timeline.csv"
print_info "Running psort to generate timeline..."
print_info "Output file: $CSV_OUTPUT"

# Build psort command with optional date filter
if [ -n "$START_DATE" ]; then
    print_info "Applying date filter: Events from $START_DATE onwards"
    psort.py \
      -o dynamic \
      -w "$CSV_OUTPUT" \
      "$PLASO_FILE" \
      "date > '${START_DATE}'"
else
    psort.py \
      -o dynamic \
      -w "$CSV_OUTPUT" \
      "$PLASO_FILE"
fi

if [ $? -ne 0 ]; then
    print_error "psort.py failed"
    exit 1
fi

print_info "Timeline generation complete!"
echo ""
print_info "=== Case Processing Summary ==="
print_info "Case Directory: $CASE_DIR"
print_info "Extracted Data: $EXTRACTED_DIR"
print_info "Plaso Storage: $PLASO_FILE"
print_info "Timeline CSV: $CSV_OUTPUT"
echo ""
print_info "You can now open the timeline in Timeline Explorer or your preferred tool"

# Optional: Display file sizes
print_info "File sizes:"
du -h "$PLASO_FILE" 2>/dev/null && echo "  Plaso file: $(du -h "$PLASO_FILE" | cut -f1)"
du -h "$CSV_OUTPUT" 2>/dev/null && echo "  Timeline CSV: $(du -h "$CSV_OUTPUT" | cut -f1)"

exit 0
