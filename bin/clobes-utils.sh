#!/bin/bash
# clobes-utils.sh - Utilities for CLOBES PRO

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Check if CLOBES is installed
check_clobes() {
    if ! command -v clobes >/dev/null 2>&1; then
        echo -e "${RED}CLOBES PRO is not installed${NC}"
        echo "Install with: curl -fsSL https://raw.githubusercontent.com/gopu-inc/clobes/main/install.sh | sudo sh"
        return 1
    fi
    return 0
}

# Batch download
batch_download() {
    if [ $# -lt 2 ]; then
        echo "Usage: $0 <url_list_file> <output_dir>"
        return 1
    fi
    
    check_clobes || return 1
    
    local url_file="$1"
    local output_dir="$2"
    
    mkdir -p "$output_dir"
    
    echo "Downloading files from $url_file to $output_dir"
    
    while IFS= read -r url; do
        if [ -n "$url" ]; then
            filename=$(basename "$url")
            echo "Downloading: $filename"
            clobes network download "$url" "$output_dir/$filename"
        fi
    done < "$url_file"
}

# Network monitor
network_monitor() {
    check_clobes || return 1
    
    echo "Network Monitoring - Press Ctrl+C to stop"
    echo "══════════════════════════════════════════════════"
    
    while true; do
        clear
        echo "$(date)"
        echo "══════════════════════════════════════════════════"
        
        # Public IP
        echo -e "${CYAN}Public IP:${NC}"
        clobes network myip 2>/dev/null
        
        # Ping test
        echo -e "\n${CYAN}Ping Test:${NC}"
        clobes network ping google.com -c 2 2>/dev/null | tail -2
        
        # Speed test (quick)
        echo -e "\n${CYAN}Quick Speed Test:${NC}"
        curl -s https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py |             python3 - --simple 2>/dev/null || echo "Speed test not available"
        
        sleep 10
    done
}

# System dashboard
system_dashboard() {
    check_clobes || return 1
    
    while true; do
        clear
        echo "🚀 CLOBES PRO System Dashboard"
        echo "══════════════════════════════════════════════════"
        
        # System info
        echo -e "${CYAN}System Information:${NC}"
        clobes system info | head -10
        
        # Processes
        echo -e "\n${CYAN}Top Processes:${NC}"
        clobes system processes 2>/dev/null | head -10
        
        # Memory
        echo -e "\n${CYAN}Memory Usage:${NC}"
        clobes system memory 2>/dev/null
        
        # Disks
        echo -e "\n${CYAN}Disk Usage:${NC}"
        clobes system disks 2>/dev/null | head -10
        
        echo -e "\n${YELLOW}Press Enter to refresh, Ctrl+C to exit...${NC}"
        read -t 5 dummy
    done
}

# File analyzer
file_analyzer() {
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <file_or_directory>"
        return 1
    fi
    
    check_clobes || return 1
    
    local target="$1"
    
    echo "🔍 File Analyzer: $target"
    echo "══════════════════════════════════════════════════"
    
    if [ -f "$target" ]; then
        # Single file analysis
        echo -e "${CYAN}File Information:${NC}"
        clobes file size "$target"
        
        echo -e "\n${CYAN}Hashes:${NC}"
        clobes file hash "$target" md5
        clobes file hash "$target" sha256
        
        echo -e "\n${CYAN}File Type:${NC}"
        file "$target"
        
    elif [ -d "$target" ]; then
        # Directory analysis
        echo -e "${CYAN}Directory Size:${NC}"
        clobes file size "$target"
        
        echo -e "\n${CYAN}File Count:${NC}"
        find "$target" -type f | wc -l
        
        echo -e "\n${CYAN}Top 10 Largest Files:${NC}"
        find "$target" -type f -exec du -h {} + | sort -rh | head -10
    fi
}

# Show help
show_help() {
    echo "CLOBES PRO Utilities"
    echo "══════════════════════════════════════════════════"
    echo ""
    echo "Available commands:"
    echo "  batch-download <url_file> <output_dir>  - Download multiple files"
    echo "  network-monitor                         - Monitor network status"
    echo "  system-dashboard                        - System monitoring dashboard"
    echo "  file-analyzer <path>                    - Analyze file/directory"
    echo "  help                                    - Show this help"
    echo ""
}

# Main
case "$1" in
    "batch-download")
        shift
        batch_download "$@"
        ;;
    "network-monitor")
        network_monitor
        ;;
    "system-dashboard")
        system_dashboard
        ;;
    "file-analyzer")
        shift
        file_analyzer "$@"
        ;;
    "help"|"")
        show_help
        ;;
    *)
        echo "Unknown command: $1"
        show_help
        exit 1
        ;;
esac
