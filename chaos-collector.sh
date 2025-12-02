#!/usr/bin/env bash

###############################################################################
# Chaos Data Collector Pro - Advanced Target Aggregation System
# Version: 2.0.0 | Author: Security Operations Team
# Description: Professional tool for aggregating security reconnaissance data
# Usage: ./chaos-collector.sh [OPTIONS]
###############################################################################

set -euo pipefail
shopt -s nullglob

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Configuration
CONFIG_FILE="${HOME}/.chaos_collector.conf"
LOG_FILE="chaos_collector_$(date +%Y%m%d_%H%M%S).log"
TEMP_DIR="chaos_temp_$(date +%s)"
MAX_RETRIES=3
TIMEOUT=30
USER_AGENT="Chaos-Collector-Pro/2.0 (+https://github.com/security-tools)"
PARALLEL_DOWNLOADS=5
VALIDATE_DOMAINS=true
REMOVE_DUPLICATES=true
ENABLE_COMPRESSION=true
SEND_NOTIFICATIONS=false

# Default values
OUTPUT_DIR="chaos_data"
OUTPUT_FILE="aggregated_targets.txt"
INDEX_URL="https://chaos-data.projectdiscovery.io/index.json"
RESUME_DOWNLOAD=false
VERBOSE=false
QUIET=false
DRY_RUN=false
CLEANUP=true
BACKUP_EXISTING=true

# Stats tracking
STATS_DOWNLOADED=0
STATS_FAILED=0
STATS_EXTRACTED=0
STATS_TOTAL_URLS=0
STATS_TOTAL_DOMAINS=0
STATS_DUPLICATES_REMOVED=0
START_TIME=$(date +%s)

# Load configuration if exists
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        source "$CONFIG_FILE"
        log_message "INFO" "Configuration loaded from $CONFIG_FILE"
    fi
}

# Save configuration
save_config() {
    cat > "$CONFIG_FILE" << EOF
# Chaos Collector Configuration
OUTPUT_DIR="$OUTPUT_DIR"
OUTPUT_FILE="$OUTPUT_FILE"
INDEX_URL="$INDEX_URL"
PARALLEL_DOWNLOADS=$PARALLEL_DOWNLOADS
VALIDATE_DOMAINS=$VALIDATE_DOMAINS
REMOVE_DUPLICATES=$REMOVE_DUPLICATES
ENABLE_COMPRESSION=$ENABLE_COMPRESSION
MAX_RETRIES=$MAX_RETRIES
TIMEOUT=$TIMEOUT
USER_AGENT="$USER_AGENT"
EOF
    log_message "INFO" "Configuration saved to $CONFIG_FILE"
}

# Logging functions
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "ERROR") color="$RED" ;;
        "WARN") color="$YELLOW" ;;
        "INFO") color="$GREEN" ;;
        "DEBUG") color="$BLUE" ;;
        *) color="$NC" ;;
    esac
    
    if [[ "$VERBOSE" == true ]] || [[ "$level" != "DEBUG" ]]; then
        if [[ "$QUIET" == false ]]; then
            echo -e "${color}[$timestamp] [$level]${NC} $message"
        fi
    fi
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Print banner
print_banner() {
    cat << "EOF"

     ██████╗██╗  ██╗ █████╗  ██████╗ ███████╗    ██████╗ ██████╗ ██╗     
    ██╔════╝██║  ██║██╔══██╗██╔════╝ ██╔════╝    ██╔══██╗██╔══██╗██║     
    ██║     ███████║███████║██║  ███╗███████╗    ██║  ██║██████╔╝██║     
    ██║     ██╔══██║██╔══██║██║   ██║╚════██║    ██║  ██║██╔═══╝ ██║     
    ╚██████╗██║  ██║██║  ██║╚██████╔╝███████║    ██████╔╝██║     ███████╗
     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═════╝ ╚═╝     ╚══════╝
                                                                         
    ██████╗  ██████╗ ██╗   ██╗███████╗███████╗████████╗███████╗██████╗ 
    ██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
    ██║  ██║██║   ██║██║   ██║█████╗  ███████╗   ██║   █████╗  ██████╔╝
    ██║  ██║██║   ██║╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝ ╚████╔╝ ███████╗███████║   ██║   ███████╗██║  ██║
    ╚═════╝  ╚═════╝   ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    
    Chaos Data Collector Pro v2.0 - Advanced Target Aggregation System
    For authorized security research and reconnaissance purposes only
EOF
    echo ""
}

# Print usage
print_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  -o, --output-dir DIR      Output directory (default: $OUTPUT_DIR)
  -f, --output-file FILE    Output filename (default: $OUTPUT_FILE)
  -u, --url URL             Custom index.json URL
  -p, --parallel NUM        Parallel downloads (default: $PARALLEL_DOWNLOADS)
  -r, --retries NUM         Max retries per download (default: $MAX_RETRIES)
  -t, --timeout SEC         Timeout in seconds (default: $TIMEOUT)
  -c, --config FILE         Custom config file
  -v, --verbose             Enable verbose output
  -q, --quiet               Suppress non-error output
  -d, --dry-run             Simulate without downloading
  -n, --no-cleanup          Keep temporary files
  -b, --no-backup           Don't backup existing files
  -s, --save-config         Save current settings to config file
  -l, --load-config         Load settings from config file
  --no-validation           Skip domain validation
  --no-deduplication        Skip duplicate removal
  --no-compression          Disable output compression
  --resume                  Resume interrupted download
  --stats                   Show statistics only
  --version                 Show version information
  -h, --help                Show this help message

Examples:
  $(basename "$0") -o my_data -p 10
  $(basename "$0") --resume --parallel 8 --no-cleanup
  $(basename "$0") -v -u "https://custom.index.json"
EOF
}

# Parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -f|--output-file)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -u|--url)
                INDEX_URL="$2"
                shift 2
                ;;
            -p|--parallel)
                PARALLEL_DOWNLOADS="$2"
                shift 2
                ;;
            -r|--retries)
                MAX_RETRIES="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                load_config
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -q|--quiet)
                QUIET=true
                VERBOSE=false
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -n|--no-cleanup)
                CLEANUP=false
                shift
                ;;
            -b|--no-backup)
                BACKUP_EXISTING=false
                shift
                ;;
            -s|--save-config)
                save_config
                exit 0
                ;;
            -l|--load-config)
                load_config
                shift
                ;;
            --no-validation)
                VALIDATE_DOMAINS=false
                shift
                ;;
            --no-deduplication)
                REMOVE_DUPLICATES=false
                shift
                ;;
            --no-compression)
                ENABLE_COMPRESSION=false
                shift
                ;;
            --resume)
                RESUME_DOWNLOAD=true
                shift
                ;;
            --stats)
                show_statistics
                exit 0
                ;;
            --version)
                echo "Chaos Data Collector Pro v2.0"
                exit 0
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                log_message "ERROR" "Unknown option: $1"
                print_usage
                exit 1
                ;;
        esac
    done
}

# Check dependencies
check_dependencies() {
    local deps=("wget" "unzip" "jq" "sort" "awk")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_message "ERROR" "Missing dependencies: ${missing_deps[*]}"
        log_message "INFO" "Install with: sudo apt-get install ${missing_deps[*]}"
        exit 1
    fi
    
    log_message "INFO" "All dependencies available"
}

# Create directory structure
setup_directories() {
    log_message "INFO" "Setting up directory structure..."
    
    mkdir -p "$OUTPUT_DIR" "$TEMP_DIR"
    
    if [[ "$BACKUP_EXISTING" == true ]] && [[ -f "$OUTPUT_DIR/$OUTPUT_FILE" ]]; then
        local backup_file="${OUTPUT_FILE%.*}_backup_$(date +%Y%m%d_%H%M%S).${OUTPUT_FILE##*.}"
        cp "$OUTPUT_DIR/$OUTPUT_FILE" "$OUTPUT_DIR/$backup_file"
        log_message "INFO" "Backup created: $backup_file"
    fi
    
    if [[ "$RESUME_DOWNLOAD" == true ]] && [[ -f "$OUTPUT_DIR/downloaded_urls.txt" ]]; then
        log_message "INFO" "Resuming from previous download"
    fi
}

# Download index.json with retry logic
download_index() {
    local retries=0
    local success=false
    
    log_message "INFO" "Downloading index from: $INDEX_URL"
    
    if [[ "$DRY_RUN" == true ]]; then
        log_message "INFO" "[DRY RUN] Would download: $INDEX_URL"
        return 0
    fi
    
    while [[ $retries -lt $MAX_RETRIES ]] && [[ $success == false ]]; do
        if wget --timeout="$TIMEOUT" --tries=1 --user-agent="$USER_AGENT" \
               -O "$TEMP_DIR/index.json" "$INDEX_URL" 2>> "$LOG_FILE"; then
            success=true
            log_message "INFO" "Index downloaded successfully"
        else
            retries=$((retries + 1))
            log_message "WARN" "Download failed (attempt $retries/$MAX_RETRIES)"
            sleep $((retries * 2))
        fi
    done
    
    if [[ $success == false ]]; then
        log_message "ERROR" "Failed to download index after $MAX_RETRIES attempts"
        exit 1
    fi
    
    # Validate JSON
    if ! jq empty "$TEMP_DIR/index.json" 2>/dev/null; then
        log_message "ERROR" "Invalid JSON received from index URL"
        exit 1
    fi
}

# Extract URLs from index.json
extract_urls() {
    log_message "INFO" "Extracting dataset URLs..."
    
    if [[ ! -f "$TEMP_DIR/index.json" ]]; then
        log_message "ERROR" "Index file not found"
        exit 1
    fi
    
    # Extract URLs using jq
    jq -r '.[] | select(.URL) | .URL' "$TEMP_DIR/index.json" > "$TEMP_DIR/urls.txt"
    
    STATS_TOTAL_URLS=$(wc -l < "$TEMP_DIR/urls.txt" | tr -d ' ')
    
    if [[ "$STATS_TOTAL_URLS" -eq 0 ]]; then
        log_message "ERROR" "No URLs found in index"
        exit 1
    fi
    
    log_message "INFO" "Found $STATS_TOTAL_URLS dataset URLs"
    
    # Filter already downloaded URLs if resuming
    if [[ "$RESUME_DOWNLOAD" == true ]] && [[ -f "$OUTPUT_DIR/downloaded_urls.txt" ]]; then
        grep -F -x -v -f "$OUTPUT_DIR/downloaded_urls.txt" "$TEMP_DIR/urls.txt" > "$TEMP_DIR/urls_to_download.txt"
        mv "$TEMP_DIR/urls_to_download.txt" "$TEMP_DIR/urls.txt"
        local remaining=$(wc -l < "$TEMP_DIR/urls.txt" | tr -d ' ')
        log_message "INFO" "Resuming: $remaining URLs remaining"
    fi
}

# Download datasets in parallel
download_datasets() {
    log_message "INFO" "Downloading datasets (parallel: $PARALLEL_DOWNLOADS)..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_message "INFO" "[DRY RUN] Would download $(wc -l < "$TEMP_DIR/urls.txt") files"
        return 0
    fi
    
    # Create download directory
    mkdir -p "$TEMP_DIR/downloads"
    
    # Download function
    download_single() {
        local url="$1"
        local filename=$(basename "$url")
        local retries=0
        local success=false
        
        while [[ $retries -lt $MAX_RETRIES ]] && [[ $success == false ]]; do
            if wget --timeout="$TIMEOUT" --tries=1 --user-agent="$USER_AGENT" \
                   -O "$TEMP_DIR/downloads/$filename" "$url" 2>> "$LOG_FILE"; then
                success=true
                echo "$url" >> "$OUTPUT_DIR/downloaded_urls.txt"
                log_message "DEBUG" "Downloaded: $filename"
                echo "success"
            else
                retries=$((retries + 1))
                log_message "WARN" "Failed to download $filename (attempt $retries/$MAX_RETRIES)"
                sleep $((retries * 1))
            fi
        done
        
        if [[ $success == false ]]; then
            log_message "ERROR" "Permanently failed: $filename"
            echo "failed"
        fi
    }
    
    # Export function for parallel
    export -f download_single
    export TEMP_DIR OUTPUT_DIR LOG_FILE TIMEOUT USER_AGENT MAX_RETRIES
    export -f log_message
    
    # Run downloads in parallel
    local downloaded=0
    local failed=0
    
    while IFS= read -r url || [[ -n "$url" ]]; do
        echo "$url"
    done < "$TEMP_DIR/urls.txt" | xargs -I {} -P "$PARALLEL_DOWNLOADS" bash -c '
        result=$(download_single "$1")
        if [[ "$result" == "success" ]]; then
            echo "success" >> "$TEMP_DIR/download_results.txt"
        elif [[ "$result" == "failed" ]]; then
            echo "failed" >> "$TEMP_DIR/download_results.txt"
        fi
    ' -- {}
    
    # Count results
    if [[ -f "$TEMP_DIR/download_results.txt" ]]; then
        STATS_DOWNLOADED=$(grep -c "success" "$TEMP_DIR/download_results.txt" || echo 0)
        STATS_FAILED=$(grep -c "failed" "$TEMP_DIR/download_results.txt" || echo 0)
    fi
    
    log_message "INFO" "Downloads completed: $STATS_DOWNLOADED success, $STATS_FAILED failed"
}

# Extract ZIP files
extract_archives() {
    log_message "INFO" "Extracting archives..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_message "INFO" "[DRY RUN] Would extract ZIP files"
        return 0
    fi
    
    mkdir -p "$TEMP_DIR/extracted"
    
    for zipfile in "$TEMP_DIR"/downloads/*.zip; do
        if [[ -f "$zipfile" ]]; then
            local basename=$(basename "$zipfile" .zip)
            local extract_dir="$TEMP_DIR/extracted/$basename"
            
            mkdir -p "$extract_dir"
            
            if unzip -q -o "$zipfile" -d "$extract_dir" 2>> "$LOG_FILE"; then
                STATS_EXTRACTED=$((STATS_EXTRACTED + 1))
                log_message "DEBUG" "Extracted: $(basename "$zipfile")"
            else
                log_message "WARN" "Failed to extract: $(basename "$zipfile")"
            fi
        fi
    done
    
    log_message "INFO" "Extracted $STATS_EXTRACTED archives"
}

# Validate domains (basic format check)
validate_domains() {
    if [[ "$VALIDATE_DOMAINS" != true ]]; then
        log_message "INFO" "Skipping domain validation"
        return 0
    fi
    
    log_message "INFO" "Validating domain format..."
    
    # Simple domain format regex
    local domain_regex='^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    for file in "$TEMP_DIR"/extracted/**/*.txt; do
        if [[ -f "$file" ]]; then
            local temp_file="${file}.validated"
            
            # Filter lines matching domain pattern
            grep -E "$domain_regex" "$file" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' > "$temp_file"
            
            local original_count=$(wc -l < "$file" 2>/dev/null || echo 0)
            local validated_count=$(wc -l < "$temp_file" 2>/dev/null || echo 0)
            
            if [[ $validated_count -lt $original_count ]]; then
                log_message "DEBUG" "Filtered $((original_count - validated_count)) invalid entries from $(basename "$file")"
            fi
            
            mv "$temp_file" "$file"
        fi
    done
}

# Remove duplicates
deduplicate() {
    if [[ "$REMOVE_DUPLICATES" != true ]]; then
        log_message "INFO" "Skipping deduplication"
        return 0
    fi
    
    log_message "INFO" "Removing duplicates..."
    
    # Create a single file for sorting
    cat "$TEMP_DIR"/extracted/**/*.txt 2>/dev/null > "$TEMP_DIR/all_unsorted.txt" || true
    
    local before_count=$(wc -l < "$TEMP_DIR/all_unsorted.txt" 2>/dev/null | tr -d ' ' || echo 0)
    
    if [[ $before_count -eq 0 ]]; then
        log_message "WARN" "No data to deduplicate"
        return 0
    fi
    
    # Sort and remove duplicates
    sort -u "$TEMP_DIR/all_unsorted.txt" > "$TEMP_DIR/all_unique.txt"
    
    local after_count=$(wc -l < "$TEMP_DIR/all_unique.txt" | tr -d ' ')
    STATS_DUPLICATES_REMOVED=$((before_count - after_count))
    STATS_TOTAL_DOMAINS=$after_count
    
    log_message "INFO" "Removed $STATS_DUPLICATES_REMOVED duplicates"
    log_message "INFO" "Unique domains: $STATS_TOTAL_DOMAINS"
}

# Generate final output
generate_output() {
    log_message "INFO" "Generating final output..."
    
    if [[ "$DRY_RUN" == true ]]; then
        log_message "INFO" "[DRY RUN] Would create output file"
        return 0
    fi
    
    # Create main output file
    if [[ -f "$TEMP_DIR/all_unique.txt" ]]; then
        cp "$TEMP_DIR/all_unique.txt" "$OUTPUT_DIR/$OUTPUT_FILE"
    elif [[ -f "$TEMP_DIR/all_unsorted.txt" ]]; then
        sort -u "$TEMP_DIR/all_unsorted.txt" > "$OUTPUT_DIR/$OUTPUT_FILE"
    else
        cat "$TEMP_DIR"/extracted/**/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/$OUTPUT_FILE" || true
    fi
    
    # Create additional formatted outputs
    if [[ -f "$OUTPUT_DIR/$OUTPUT_FILE" ]]; then
        # Create domain-only version
        awk -F. '{print $NF}' "$OUTPUT_DIR/$OUTPUT_FILE" | sort | uniq -c | sort -rn > "$OUTPUT_DIR/tld_distribution.txt"
        
        # Create subdomain count
        awk -F. '{print $(NF-1)"."$NF}' "$OUTPUT_DIR/$OUTPUT_FILE" | sort | uniq -c | sort -rn > "$OUTPUT_DIR/domain_distribution.txt"
        
        # Create wildcard patterns for masscan/nmap
        awk -F. '{print "*."$(NF-1)"."$NF}' "$OUTPUT_DIR/$OUTPUT_FILE" | sort -u > "$OUTPUT_DIR/wildcard_patterns.txt"
        
        log_message "INFO" "Main output: $OUTPUT_DIR/$OUTPUT_FILE ($(wc -l < "$OUTPUT_DIR/$OUTPUT_FILE" | tr -d ' ') domains)"
    fi
    
    # Compress if enabled
    if [[ "$ENABLE_COMPRESSION" == true ]]; then
        log_message "INFO" "Compressing output files..."
        tar -czf "$OUTPUT_DIR/chaos_data_$(date +%Y%m%d).tar.gz" -C "$OUTPUT_DIR" \
            "$OUTPUT_FILE" \
            "tld_distribution.txt" \
            "domain_distribution.txt" \
            "wildcard_patterns.txt" 2>/dev/null || true
    fi
}

# Cleanup temporary files
cleanup() {
    if [[ "$CLEANUP" == true ]]; then
        log_message "INFO" "Cleaning up temporary files..."
        rm -rf "$TEMP_DIR"
        log_message "INFO" "Cleanup completed"
    else
        log_message "INFO" "Temporary files kept in: $TEMP_DIR"
    fi
}

# Show statistics
show_statistics() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    cat << EOF

╔══════════════════════════════════════════════════════════════╗
║                   COLLECTION STATISTICS                      ║
╠══════════════════════════════════════════════════════════════╣
║  Total URLs in index:        $(printf "%25s" "$STATS_TOTAL_URLS") ║
║  Successfully downloaded:    $(printf "%25s" "$STATS_DOWNLOADED") ║
║  Failed downloads:           $(printf "%25s" "$STATS_FAILED") ║
║  Archives extracted:         $(printf "%25s" "$STATS_EXTRACTED") ║
║  Total domains collected:    $(printf "%25s" "$STATS_TOTAL_DOMAINS") ║
║  Duplicates removed:         $(printf "%25s" "$STATS_DUPLICATES_REMOVED") ║
║  Collection duration:        $(printf "%25s" "${duration}s") ║
║  Output directory:           $(printf "%25s" "$OUTPUT_DIR") ║
║  Output file:                $(printf "%25s" "$OUTPUT_FILE") ║
║  Log file:                   $(printf "%25s" "$LOG_FILE") ║
╚══════════════════════════════════════════════════════════════╝

Additional files created:
  • tld_distribution.txt    - Top Level Domain statistics
  • domain_distribution.txt - Domain frequency analysis  
  • wildcard_patterns.txt   - Patterns for wildcard scanning
  • downloaded_urls.txt     - Resume tracking file

EOF
}

# Send notification (if configured)
send_notification() {
    if [[ "$SEND_NOTIFICATIONS" == true ]]; then
        # Implement notification logic (email, Slack, etc.)
        log_message "INFO" "Notification would be sent here"
    fi
}

# Main execution flow
main() {
    print_banner
    parse_arguments "$@"
    check_dependencies
    load_config
    setup_directories
    
    log_message "INFO" "Starting Chaos Data Collector Pro"
    log_message "INFO" "Output directory: $OUTPUT_DIR"
    log_message "INFO" "Index URL: $INDEX_URL"
    
    # Main pipeline
    download_index
    extract_urls
    download_datasets
    extract_archives
    validate_domains
    deduplicate
    generate_output
    cleanup
    show_statistics
    send_notification
    
    log_message "INFO" "Collection completed successfully"
}

# Handle script termination
trap 'log_message "ERROR" "Script interrupted by user"; cleanup; exit 1' INT TERM

# Run main function
main "$@"