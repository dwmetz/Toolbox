#!/bin/bash

# ============================================================================
#  UAC Timeline Generator v1.0
#  Author: Doug Metz | Baker Street Forensics
#  https://bakerstreetforensics.com
# ============================================================================

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

print_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $1"
}

# Function to display usage
usage() {
    echo "Usage: $0 -t <uac-tar-gz-file> -c <case-name> [-d <cases-directory>] [-s <start-date>]"
    echo ""
    echo "Options:"
    echo "  -t    Path to UAC tar.gz file (required)"
    echo "  -c    Case name for the new case directory (required)"
    echo "  -d    Base directory for cases (default: ~/cases)"
    echo "  -s    Start date for timeline filter (format: YYYY-MM-DD)"
    echo "  -h    Display this help message"
    echo ""
    echo "Example:"
    echo "  $0 -t /path/to/uac-collection.tar.gz -c linux_server_2024"
    echo "  $0 -t /path/to/uac-collection.tar.gz -c linux_server_2024 -s 2024-06-01"
    echo ""
    echo "Note: Script auto-detects Linux vs macOS collections"
    exit 1
}

# Function to detect OS type from collection
detect_os_type() {
    local root_dir="$1"
    
    # Check for macOS-specific directories
    if [ -d "$root_dir/Applications" ] && [ -d "$root_dir/Library" ] && [ -d "$root_dir/System" ]; then
        echo "macos"
        return 0
    fi
    
    # Check for Linux-specific directories
    if [ -d "$root_dir/etc" ] && [ -d "$root_dir/var" ]; then
        echo "linux"
        return 0
    fi
    
    # Unable to determine
    echo "unknown"
    return 1
}

# Default values
CASES_BASE_DIR="$HOME/cases"
TAR_FILE=""
CASE_NAME=""
START_DATE=""

# Parse command line arguments
while getopts "t:c:d:s:h" opt; do
    case $opt in
        t)
            TAR_FILE="$OPTARG"
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
if [ -z "$TAR_FILE" ] || [ -z "$CASE_NAME" ]; then
    print_error "Missing required arguments"
    usage
fi

# Validate tar.gz file exists
if [ ! -f "$TAR_FILE" ]; then
    print_error "tar.gz file not found: $TAR_FILE"
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

# Extract tar.gz file, filtering out macOS extended attribute warnings
print_info "Extracting UAC collection..."
tar -xzf "$TAR_FILE" -C "$EXTRACTED_DIR" 2>&1 | grep -v "Ignoring unknown extended header keyword" | grep -v "^tar:" || true

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    print_error "Failed to extract tar.gz file"
    exit 1
fi

print_info "Extraction complete"

# Find the [root] directory
ROOT_PATH=$(find "$EXTRACTED_DIR" -type d -name "\[root\]" | head -n 1)

if [ -z "$ROOT_PATH" ]; then
    print_error "Could not find [root] directory in extracted files"
    print_info "Contents of extracted directory:"
    ls -la "$EXTRACTED_DIR"
    exit 1
fi

print_info "Found UAC root at: $ROOT_PATH"

# Detect OS type
print_info "Detecting collection OS type..."
OS_TYPE=$(detect_os_type "$ROOT_PATH")

if [ "$OS_TYPE" = "unknown" ]; then
    print_warning "Could not auto-detect OS type"
    print_warning "Will proceed without OS-specific parser (Plaso will auto-detect)"
    PARSER_FLAG=""
else
    print_info "Detected OS type: $OS_TYPE"
    PARSER_FLAG="--parsers $OS_TYPE"
fi

# Run log2timeline
PLASO_FILE="$CASE_DIR/uac_${OS_TYPE}.plaso"
print_info "Running log2timeline (this may take a while)..."
print_info "Output file: $PLASO_FILE"

if [ -n "$PARSER_FLAG" ]; then
    print_debug "Using parser: $PARSER_FLAG"
    log2timeline.py \
      --storage-file "$PLASO_FILE" \
      $PARSER_FLAG \
      --hashers none \
      "$ROOT_PATH"
else
    print_debug "Using auto-detection (no specific parser)"
    log2timeline.py \
      --storage-file "$PLASO_FILE" \
      --hashers none \
      "$ROOT_PATH"
fi

if [ $? -ne 0 ]; then
    print_error "log2timeline.py failed"
    exit 1
fi

print_info "log2timeline processing complete"

# Run psort to create timeline
CSV_OUTPUT="$CASE_DIR/uac_${OS_TYPE}_timeline.csv"
print_info "Running psort to generate timeline..."
print_info "Output file: $CSV_OUTPUT"

# Build psort command with optional date filter
PSORT_CMD="psort.py -o dynamic -w \"$CSV_OUTPUT\""

if [ -n "$START_DATE" ]; then
    print_info "Applying date filter: Events from $START_DATE onwards"
    PSORT_CMD="$PSORT_CMD --date-filter \"$START_DATE..\""
fi

PSORT_CMD="$PSORT_CMD \"$PLASO_FILE\""

eval $PSORT_CMD

if [ $? -ne 0 ]; then
    print_error "psort.py failed"
    exit 1
fi

print_info "Timeline generation complete!"
echo ""
print_info "=== Case Processing Summary ==="
print_info "Case Directory: $CASE_DIR"
print_info "OS Type Detected: $OS_TYPE"
print_info "Extracted Data: $EXTRACTED_DIR"
print_info "Plaso Storage: $PLASO_FILE"
print_info "Timeline CSV: $CSV_OUTPUT"

# Check if bodyfile exists and note it
BODYFILE=$(find "$EXTRACTED_DIR" -type f -name "bodyfile" | head -n 1)
if [ -n "$BODYFILE" ]; then
    print_info "UAC Bodyfile: $BODYFILE (available for reference)"
fi

echo ""
print_info "You can now open the timeline in Timeline Explorer or your preferred tool"

# Optional: Display file sizes
print_info "File sizes:"
du -h "$PLASO_FILE" 2>/dev/null && echo "  Plaso file: $(du -h "$PLASO_FILE" | cut -f1)"
du -h "$CSV_OUTPUT" 2>/dev/null && echo "  Timeline CSV: $(du -h "$CSV_OUTPUT" | cut -f1)"

exit 0
