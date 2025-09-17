#!/bin/bash

# Kali Linux Network Security Audit Script - Enhanced Edition
# Description: Comprehensive network security check with export and tool integration
# Author: Your Friendly Neighborhood Sysadmin
# Version: 2.0 - Now with more boom!

# Color definitions for pretty output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/audit_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname)
EXPORT_HTML=false
EXPORT_JSON=false
RUN_NMAP=false
RUN_DISCOVERY=false
VERBOSE=false

# Results storage for export
declare -A AUDIT_RESULTS

# Function to print colored headers
print_header() {
    echo -e "\n${CYAN}========================================${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${CYAN}========================================${NC}"

    # Store in results array for export
    AUDIT_RESULTS["headers"]+="$1|"
}

# Function to print status messages
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
    AUDIT_RESULTS["status"]+="✓ $1|"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    AUDIT_RESULTS["warnings"]+="! $1|"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    AUDIT_RESULTS["errors"]+="✗ $1|"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    AUDIT_RESULTS["info"]+="i $1|"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to show usage
show_usage() {
    echo "Kali Linux Network Security Audit Script v2.0"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --verbose       Enable verbose output"
    echo "  -j, --json          Export results to JSON file"
    echo "  -H, --html          Export results to HTML report"
    echo "  -n, --nmap          Run nmap self-scan"
    echo "  -d, --discovery     Run network discovery tools"
    echo "  -a, --all           Run all checks and exports (equivalent to -jHnd)"
    echo "  -o, --output DIR    Specify output directory (default: ./audit_results)"
    echo ""
    echo "Examples:"
    echo "  $0                  Basic audit"
    echo "  $0 -a               Full audit with all features"
    echo "  $0 -jH              Audit with JSON and HTML export"
    echo "  $0 -nd              Audit with nmap and discovery tools"
    echo ""
}

# Function to parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -j|--json)
                EXPORT_JSON=true
                shift
                ;;
            -H|--html)
                EXPORT_HTML=true
                shift
                ;;
            -n|--nmap)
                RUN_NMAP=true
                shift
                ;;
            -d|--discovery)
                RUN_DISCOVERY=true
                shift
                ;;
            -a|--all)
                EXPORT_JSON=true
                EXPORT_HTML=true
                RUN_NMAP=true
                RUN_DISCOVERY=true
                shift
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Function to create output directory
setup_output_dir() {
    if [[ "$EXPORT_HTML" == true ]] || [[ "$EXPORT_JSON" == true ]]; then
        mkdir -p "$OUTPUT_DIR"
        print_info "Output directory: $OUTPUT_DIR"
    fi
}

# Main function to start the audit
main() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
    ██╗  ██╗ █████╗ ██╗     ██╗    ███╗   ██╗███████╗████████╗     █████╗ ██╗   ██╗██████╗ ██╗████████╗
    ██║ ██╔╝██╔══██╗██║     ██║    ████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
    █████╔╝ ███████║██║     ██║    ██╔██╗ ██║█████╗     ██║       ███████║██║   ██║██║  ██║██║   ██║
    ██╔═██╗ ██╔══██║██║     ██║    ██║╚██╗██║██╔══╝     ██║       ██╔══██║██║   ██║██║  ██║██║   ██║
    ██║  ██╗██║  ██║███████╗██║    ██║ ╚████║███████╗   ██║       ██║  ██║╚██████╔╝██████╔╝██║   ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝
EOF
    echo -e "${NC}"
    echo -e "${WHITE}Network Security Audit Script v2.0 - $(date)${NC}"

    # Show enabled features
    echo -e "${BLUE}Enabled Features:${NC}"
    [[ "$EXPORT_JSON" == true ]] && echo -e "  ${GREEN}✓${NC} JSON Export"
    [[ "$EXPORT_HTML" == true ]] && echo -e "  ${GREEN}✓${NC} HTML Report"
    [[ "$RUN_NMAP" == true ]] && echo -e "  ${GREEN}✓${NC} Nmap Self-Scan"
    [[ "$RUN_DISCOVERY" == true ]] && echo -e "  ${GREEN}✓${NC} Network Discovery"
    [[ "$VERBOSE" == true ]] && echo -e "  ${GREEN}✓${NC} Verbose Mode"

    # Check if running as root for some commands
    if [[ $EUID -eq 0 ]]; then
        print_status "Running as root - full access mode"
    else
        print_warning "Running as user - some checks may be limited"
    fi

    # Initialize audit results
    AUDIT_RESULTS["timestamp"]="$(date)"
    AUDIT_RESULTS["hostname"]="$HOSTNAME"
    AUDIT_RESULTS["user"]="$(whoami)"

    # Start the audit
    check_system_info
    check_network_interfaces
    check_listening_ports
    check_established_connections
    check_firewall_status
    check_running_services
    check_suspicious_processes
    check_network_configuration
    check_kali_specific_services

    # Enhanced features
    if [[ "$RUN_NMAP" == true ]]; then
        run_nmap_self_scan
    fi

    if [[ "$RUN_DISCOVERY" == true ]]; then
        run_network_discovery
    fi

    # Specialized vulnerability scans
    run_specialized_scans

    security_recommendations

    # Export results
    if [[ "$EXPORT_JSON" == true ]]; then
        export_json
    fi

    if [[ "$EXPORT_HTML" == true ]]; then
        export_html
    fi
}

# System information
check_system_info() {
    print_header "SYSTEM INFORMATION"

    hostname_info=$(hostname)
    kernel_info=$(uname -r)
    distro_info=$(lsb_release -d 2>/dev/null | cut -f2 || echo "Unknown")
    uptime_info=$(uptime -p 2>/dev/null || uptime)
    load_info=$(uptime | awk -F'load average:' '{print $2}')

    echo -e "${BLUE}Hostname:${NC} $hostname_info"
    echo -e "${BLUE}Kernel:${NC} $kernel_info"
    echo -e "${BLUE}Distro:${NC} $distro_info"
    echo -e "${BLUE}Uptime:${NC} $uptime_info"
    echo -e "${BLUE}Load Average:${NC} $load_info"

    # Store system info
    AUDIT_RESULTS["system_kernel"]="$kernel_info"
    AUDIT_RESULTS["system_distro"]="$distro_info"
    AUDIT_RESULTS["system_uptime"]="$uptime_info"
    AUDIT_RESULTS["system_load"]="$load_info"

    # Check if this is actually Kali
    if grep -q "kali" /etc/os-release 2>/dev/null; then
        print_status "Confirmed Kali Linux system"
        AUDIT_RESULTS["kali_confirmed"]="true"
    else
        print_warning "This doesn't appear to be Kali Linux"
        AUDIT_RESULTS["kali_confirmed"]="false"
    fi
}

# Network interface information
check_network_interfaces() {
    print_header "NETWORK INTERFACES"

    interface_info=""

    # Show all interfaces with IP addresses
    if command_exists ip; then
        echo -e "${BLUE}Active Network Interfaces:${NC}"
        while IFS= read -r line; do
            if [[ $line =~ ^[0-9]+: ]]; then
                echo -e "${CYAN}$line${NC}"
                interface_info+="$line\n"
            else
                echo -e "  $line"
                interface_info+="  $line\n"
            fi
        done < <(ip -4 addr show | grep -E "(inet|^[0-9]+:)")
    else
        print_warning "ip command not found, falling back to ifconfig"
        interface_info=$(ifconfig | grep -E "(^[a-zA-Z0-9]+:|inet )")
    fi

    AUDIT_RESULTS["network_interfaces"]="$interface_info"

    # Check for promiscuous mode (potential monitoring)
    echo -e "\n${BLUE}Checking for promiscuous mode interfaces:${NC}"
    if ip link show | grep -q PROMISC; then
        promisc_info=$(ip link show | grep PROMISC)
        print_warning "Found interfaces in promiscuous mode:"
        echo "$promisc_info"
        AUDIT_RESULTS["promiscuous_mode"]="$promisc_info"
    else
        print_status "No interfaces in promiscuous mode"
        AUDIT_RESULTS["promiscuous_mode"]="none"
    fi

    # Check for wireless interfaces
    if command_exists iwconfig; then
        wireless_info=$(iwconfig 2>/dev/null | grep -v "no wireless extensions" | head -5)
        if [[ -n "$wireless_info" ]]; then
            echo -e "\n${BLUE}Wireless Interfaces:${NC}"
            echo "$wireless_info"
            AUDIT_RESULTS["wireless_interfaces"]="$wireless_info"
        fi
    fi
}

# Check listening ports and services
check_listening_ports() {
    print_header "LISTENING PORTS & SERVICES"

    listening_ports=""

    print_info "Checking for listening TCP ports..."
    if command_exists ss; then
        echo -e "${BLUE}TCP Listening Ports:${NC}"
        while IFS= read -r line; do
            port=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
            process=$(echo "$line" | awk '{print $7}' | cut -d'"' -f2)
            if [[ $port -lt 1024 ]]; then
                echo -e "${RED}[PRIVILEGED]${NC} $line"
                listening_ports+="PRIVILEGED: $line\n"
            else
                echo -e "${GREEN}[USER]${NC} $line"
                listening_ports+="USER: $line\n"
            fi
        done < <(ss -tulnp | grep LISTEN)
    else
        print_warning "ss command not found, using netstat"
        listening_ports=$(netstat -tulnp | grep LISTEN)
        echo "$listening_ports"
    fi

    AUDIT_RESULTS["listening_ports"]="$listening_ports"

    echo -e "\n${BLUE}UDP Listening Ports:${NC}"
    udp_ports=$(ss -ulnp 2>/dev/null | grep -v "State" | head -10)
    echo "$udp_ports"
    AUDIT_RESULTS["udp_ports"]="$udp_ports"

    # Check for common dangerous ports
    dangerous_ports=(21 23 25 53 80 110 135 139 143 443 445 993 995)
    dangerous_found=""
    echo -e "\n${BLUE}Scanning for common service ports:${NC}"
    for port in "${dangerous_ports[@]}"; do
        if ss -tuln | grep -q ":$port "; then
            service_name=$(getent services $port/tcp 2>/dev/null | awk '{print $1}' || echo "unknown")
            print_warning "Port $port ($service_name) is listening"
            dangerous_found+="$port ($service_name)\n"
        fi
    done
    AUDIT_RESULTS["dangerous_ports"]="$dangerous_found"
}

# Check established connections
check_established_connections() {
    print_header "ESTABLISHED NETWORK CONNECTIONS"

    print_info "Current outbound connections (last 10):"
    established_conns=$(ss -tuln4 | grep ESTAB | head -10)
    echo "$established_conns"
    AUDIT_RESULTS["established_connections"]="$established_conns"

    # Count connections by state
    echo -e "\n${BLUE}Connection summary:${NC}"
    if command_exists ss; then
        conn_summary=$(ss -tan | awk 'NR>1 {state[$1]++} END {for (i in state) printf "  %-12s: %d\n", i, state[i]}')
        echo "$conn_summary"
        AUDIT_RESULTS["connection_summary"]="$conn_summary"
    fi

    # Check for unusual connection counts
    established_count=$(ss -tan | grep ESTAB | wc -l)
    if [[ $established_count -gt 50 ]]; then
        print_warning "High number of established connections: $established_count"
    else
        print_status "Normal connection count: $established_count"
    fi
    AUDIT_RESULTS["connection_count"]="$established_count"
}

# Comprehensive firewall check
check_firewall_status() {
    print_header "FIREWALL STATUS"

    firewall_status=""

    # Check iptables
    echo -e "${BLUE}IPTables Status:${NC}"
    if command_exists iptables; then
        rule_count=$(iptables -L | wc -l)
        if [[ $rule_count -gt 8 ]]; then
            print_status "IPTables has $rule_count rules configured"
            echo -e "${BLUE}Current iptables rules:${NC}"
            iptables_rules=$(iptables -L -n --line-numbers | head -20)
            echo "$iptables_rules"
            firewall_status+="IPTables: $rule_count rules\n$iptables_rules\n"
        else
            print_warning "IPTables appears to have minimal rules ($rule_count lines)"
            firewall_status+="IPTables: minimal rules ($rule_count lines)\n"
        fi
    else
        print_error "IPTables not found"
        firewall_status+="IPTables: not found\n"
    fi

    # Check UFW
    echo -e "\n${BLUE}UFW (Uncomplicated Firewall) Status:${NC}"
    if command_exists ufw; then
        ufw_status=$(ufw status 2>/dev/null || echo "inactive")
        if echo "$ufw_status" | grep -q "active"; then
            print_status "UFW is active"
            ufw_rules=$(ufw status numbered | head -10)
            echo "$ufw_rules"
            firewall_status+="UFW: active\n$ufw_rules\n"
        else
            print_warning "UFW is inactive"
            firewall_status+="UFW: inactive\n"
        fi
    else
        print_info "UFW not installed"
        firewall_status+="UFW: not installed\n"
    fi

    # Check firewalld
    echo -e "\n${BLUE}Firewalld Status:${NC}"
    if command_exists firewall-cmd; then
        if systemctl is-active --quiet firewalld; then
            print_status "Firewalld is active"
            firewalld_zones=$(firewall-cmd --get-active-zones 2>/dev/null)
            echo "  Zone: $firewalld_zones"
            firewall_status+="Firewalld: active - $firewalld_zones\n"
        else
            print_info "Firewalld installed but inactive"
            firewall_status+="Firewalld: inactive\n"
        fi
    else
        print_info "Firewalld not installed"
        firewall_status+="Firewalld: not installed\n"
    fi

    AUDIT_RESULTS["firewall_status"]="$firewall_status"

    # Check for any firewall
    if ! command_exists iptables && ! command_exists ufw && ! command_exists firewall-cmd; then
        print_error "NO FIREWALL PROTECTION DETECTED!"
        AUDIT_RESULTS["firewall_protection"]="none"
    else
        AUDIT_RESULTS["firewall_protection"]="present"
    fi
}

# Check running services
check_running_services() {
    print_header "RUNNING SERVICES & DAEMONS"

    services_info=""

    # SystemD services
    if command_exists systemctl; then
        echo -e "${BLUE}Active SystemD Services:${NC}"
        active_services=$(systemctl list-units --type=service --state=running --no-pager | grep -E "(ssh|apache|nginx|mysql|postgresql|ftp)" | head -10)
        echo "$active_services"
        services_info+="Active Services:\n$active_services\n"

        echo -e "\n${BLUE}Failed Services:${NC}"
        failed_services=$(systemctl list-units --type=service --state=failed --no-pager --no-legend | wc -l)
        if [[ $failed_services -gt 0 ]]; then
            print_warning "$failed_services services have failed"
            failed_list=$(systemctl list-units --type=service --state=failed --no-pager --no-legend | head -5)
            echo "$failed_list"
            services_info+="Failed Services: $failed_services\n$failed_list\n"
        else
            print_status "No failed services"
            services_info+="Failed Services: none\n"
        fi
    fi

    # Check for web servers
    echo -e "\n${BLUE}Web Server Check:${NC}"
    web_servers=("apache2" "nginx" "lighttpd" "httpd")
    web_running=""
    for server in "${web_servers[@]}"; do
        if pgrep -x "$server" >/dev/null; then
            print_warning "$server is running"
            web_running+="$server "
        fi
    done
    services_info+="Web Servers: $web_running\n"

    # Check for database servers
    echo -e "\n${BLUE}Database Server Check:${NC}"
    db_servers=("mysqld" "postgres" "mongodb" "redis-server")
    db_running=""
    for db in "${db_servers[@]}"; do
        if pgrep -x "$db" >/dev/null; then
            print_warning "$db is running"
            db_running+="$db "
        fi
    done
    services_info+="Database Servers: $db_running\n"

    AUDIT_RESULTS["services_info"]="$services_info"
}

# Check for suspicious processes
check_suspicious_processes() {
    print_header "PROCESS SECURITY ANALYSIS"

    suspicious_info=""

    print_info "Checking for processes running from unusual locations..."

    # Look for processes running from temp directories
    suspicious_paths=("/tmp" "/var/tmp" "/dev/shm")
    for path in "${suspicious_paths[@]}"; do
        if pgrep -f "^$path" >/dev/null; then
            print_warning "Processes running from $path:"
            suspicious_procs=$(pgrep -f "^$path" | xargs ps -p | tail -n +2)
            echo "$suspicious_procs"
            suspicious_info+="$path: $suspicious_procs\n"
        fi
    done

    # Check for processes with network connections
    echo -e "\n${BLUE}Processes with network connections:${NC}"
    if command_exists lsof; then
        network_procs=$(lsof -i -P -n | awk 'NR>1 {print $1, $3, $8, $9}' | sort | uniq -c | sort -nr | head -10)
        echo "$network_procs"
        suspicious_info+="Network Processes:\n$network_procs\n"
    fi

    # Look for hidden processes (basic check)
    echo -e "\n${BLUE}Process count verification:${NC}"
    ps_count=$(ps aux | wc -l)
    proc_count=$(ls /proc/[0-9]* 2>/dev/null | wc -l)
    if [[ $((ps_count - proc_count)) -gt 5 ]]; then
        print_warning "Process count mismatch detected (ps: $ps_count, /proc: $proc_count)"
        suspicious_info+="Process mismatch: ps=$ps_count proc=$proc_count\n"
    else
        print_status "Process counts match"
        suspicious_info+="Process counts: normal\n"
    fi

    AUDIT_RESULTS["suspicious_processes"]="$suspicious_info"
}

# Network configuration checks
check_network_configuration() {
    print_header "NETWORK CONFIGURATION"

    network_config=""

    # Check routing table
    echo -e "${BLUE}Routing Table:${NC}"
    if command_exists ip; then
        routing_info=$(ip route show | head -5)
    else
        routing_info=$(route -n | head -5)
    fi
    echo "$routing_info"
    network_config+="Routing:\n$routing_info\n"

    # Check DNS configuration
    echo -e "\n${BLUE}DNS Configuration:${NC}"
    if [[ -f /etc/resolv.conf ]]; then
        echo -e "${BLUE}DNS Servers:${NC}"
        dns_info=$(grep nameserver /etc/resolv.conf | head -3)
        echo "$dns_info"
        network_config+="DNS:\n$dns_info\n"
    fi

    # Check for proxy settings
    echo -e "\n${BLUE}Proxy Configuration:${NC}"
    proxy_vars=("http_proxy" "https_proxy" "ftp_proxy" "HTTP_PROXY" "HTTPS_PROXY")
    proxy_found=false
    proxy_info=""
    for var in "${proxy_vars[@]}"; do
        if [[ -n "${!var}" ]]; then
            echo "  $var: ${!var}"
            proxy_info+="$var: ${!var}\n"
            proxy_found=true
        fi
    done
    if [[ "$proxy_found" == false ]]; then
        print_status "No proxy configuration detected"
        proxy_info="none"
    fi
    network_config+="Proxy: $proxy_info\n"

    # Check network parameters
    echo -e "\n${BLUE}Network Security Parameters:${NC}"
    ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
    icmp_redirect=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || echo "unknown")
    source_route=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null || echo "unknown")

    echo -e "  IP Forwarding: $ip_forward"
    echo -e "  ICMP Redirects: $icmp_redirect"
    echo -e "  Source Routing: $source_route"

    network_config+="IP Forwarding: $ip_forward\nICMP Redirects: $icmp_redirect\nSource Routing: $source_route\n"

    if [[ "$ip_forward" == "1" ]]; then
        print_warning "IP forwarding is enabled"
    fi

    AUDIT_RESULTS["network_config"]="$network_config"
}

# Kali-specific service checks
check_kali_specific_services() {
    print_header "KALI LINUX SPECIFIC CHECKS"

    kali_info=""

    # Check for common Kali services that shouldn't be running by default
    kali_services=("apache2" "ssh" "postgresql" "mysql" "smbd" "nmbd" "snmpd")
    echo -e "${BLUE}Checking Kali-specific services:${NC}"

    for service in "${kali_services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            print_warning "$service is running"
            kali_info+="$service: running\n"
        else
            print_status "$service is stopped (good)"
            kali_info+="$service: stopped\n"
        fi
    done

    # Check for metasploit database
    echo -e "\n${BLUE}Metasploit Database Status:${NC}"
    if command_exists msfdb; then
        msfdb_status=$(msfdb status 2>/dev/null || echo "not installed")
        echo "  $msfdb_status"
        kali_info+="MSF DB: $msfdb_status\n"
    fi

    # Check for common pentesting tools running as daemons
    echo -e "\n${BLUE}Common Pentesting Tool Processes:${NC}"
    pentest_tools=("beef" "armitage" "burp" "zaproxy")
    for tool in "${pentest_tools[@]}"; do
        if pgrep -x "$tool" >/dev/null; then
            print_info "$tool is currently running"
            kali_info+="$tool: running\n"
        fi
    done

    # Check for VPN connections (common for pentesting)
    echo -e "\n${BLUE}VPN Connection Check:${NC}"
    if ip link show | grep -E "(tun|tap)" >/dev/null; then
        print_status "VPN interfaces detected:"
        vpn_interfaces=$(ip link show | grep -E "(tun|tap)" | awk '{print "  " $2}' | tr -d ':')
        echo "$vpn_interfaces"
        kali_info+="VPN: present\n$vpn_interfaces\n"
    else
        print_info "No VPN interfaces detected"
        kali_info+="VPN: none\n"
    fi

    AUDIT_RESULTS["kali_specific"]="$kali_info"
}

# Nmap self-scanning function
run_nmap_self_scan() {
    print_header "NMAP SELF-SCAN"

    if ! command_exists nmap; then
        print_error "Nmap not found - installing..."
        apt-get update && apt-get install -y nmap
    fi

    local_ip=$(ip route get 1.1.1.1 | awk '{print $7; exit}' 2>/dev/null || echo "127.0.0.1")

    print_info "Running comprehensive nmap scan on $local_ip"

    # Quick TCP scan
    echo -e "\n${BLUE}TCP Port Scan (Top 1000):${NC}"
    tcp_scan=$(nmap -sS -T4 --top-ports 1000 "$local_ip" 2>/dev/null | grep -E "(open|filtered)")
    echo "$tcp_scan"

    # UDP scan (top 100 for speed)
    echo -e "\n${BLUE}UDP Port Scan (Top 100):${NC}"
    if [[ $EUID -eq 0 ]]; then
        udp_scan=$(nmap -sU -T4 --top-ports 100 "$local_ip" 2>/dev/null | grep -E "(open|filtered)")
        echo "$udp_scan"
    else
        print_warning "UDP scan requires root privileges"
        udp_scan="requires root"
    fi

    # OS detection
    echo -e "\n${BLUE}OS Detection:${NC}"
    if [[ $EUID -eq 0 ]]; then
        os_detection=$(nmap -O "$local_ip" 2>/dev/null | grep -A5 "OS details")
        echo "$os_detection"
    else
        print_warning "OS detection requires root privileges"
        os_detection="requires root"
    fi

    # Service detection
    echo -e "\n${BLUE}Service Version Detection:${NC}"
    service_scan=$(nmap -sV -T4 "$local_ip" 2>/dev/null | grep -E "(open|version)")
    echo "$service_scan"

    # Vulnerability scan
    if [[ $EUID -eq 0 ]] && command_exists nmap; then
        echo -e "\n${BLUE}Vulnerability Scan (using NSE):${NC}"
        vuln_scan=$(nmap --script vuln "$local_ip" 2>/dev/null | grep -A3 -B1 "VULNERABLE")
        if [[ -n "$vuln_scan" ]]; then
            print_warning "Potential vulnerabilities found:"
            echo "$vuln_scan"
        else
            print_status "No obvious vulnerabilities detected"
        fi
    fi

    # Store nmap results
    AUDIT_RESULTS["nmap_tcp"]="$tcp_scan"
    AUDIT_RESULTS["nmap_udp"]="$udp_scan"
    AUDIT_RESULTS["nmap_os"]="$os_detection"
    AUDIT_RESULTS["nmap_services"]="$service_scan"
    AUDIT_RESULTS["nmap_vulns"]="$vuln_scan"
}

# Network discovery function using Kali tools
run_network_discovery() {
    print_header "NETWORK DISCOVERY TOOLS"

    local_network=$(ip route | grep -E '192\.168\.|10\.|172\.' | head -1 | awk '{print $1}')
    gateway=$(ip route | grep default | awk '{print $3}' | head -1)

    print_info "Local Network: $local_network"
    print_info "Gateway: $gateway"

    discovery_results=""

    # ARP scan using arp-scan
    if command_exists arp-scan; then
        echo -e "\n${BLUE}ARP Scan (Local Network Discovery):${NC}"
        if [[ $EUID -eq 0 ]] && [[ -n "$local_network" ]]; then
            arp_results=$(arp-scan -l 2>/dev/null | grep -v "Interface" | head -20)
            echo "$arp_results"
            discovery_results+="ARP Scan:\n$arp_results\n"
        else
            print_warning "ARP scan requires root and valid network range"
        fi
    fi

    # Netdiscover
    if command_exists netdiscover; then
        echo -e "\n${BLUE}Netdiscover (Passive Discovery):${NC}"
        if [[ $EUID -eq 0 ]] && [[ -n "$local_network" ]]; then
            print_info "Running passive netdiscover for 10 seconds..."
            timeout 10 netdiscover -r "$local_network" -P 2>/dev/null | head -10 | tail -5
        else
            print_warning "Netdiscover requires root privileges"
        fi
    fi

    # Masscan (if available)
    if command_exists masscan; then
        echo -e "\n${BLUE}Masscan (Fast Port Scan):${NC}"
        if [[ $EUID -eq 0 ]] && [[ -n "$local_network" ]]; then
            print_info "Running fast masscan on common ports..."
            mass_results=$(masscan "$local_network" -p22,23,80,443,21,25,53,135,139,445 --rate=1000 2>/dev/null | head -10)
            echo "$mass_results"
            discovery_results+="Masscan:\n$mass_results\n"
        else
            print_warning "Masscan requires root privileges"
        fi
    fi

    # RustScan (if available)
    if command_exists rustscan; then
        echo -e "\n${BLUE}RustScan (Modern Port Scanner):${NC}"
        if [[ -n "$gateway" ]]; then
            print_info "Scanning gateway with RustScan..."
            rust_results=$(rustscan -a "$gateway" --top 2>/dev/null | grep "Open" | head -10)
            echo "$rust_results"
            discovery_results+="RustScan:\n$rust_results\n"
        fi
    fi

    # Network sniffing sample (tcpdump)
    if command_exists tcpdump; then
        echo -e "\n${BLUE}Network Traffic Sample (5 seconds):${NC}"
        if [[ $EUID -eq 0 ]]; then
            print_info "Capturing network traffic sample..."
            traffic_sample=$(timeout 5 tcpdump -c 10 -n 2>/dev/null | grep -v "tcpdump")
            echo "$traffic_sample"
            discovery_results+="Traffic Sample:\n$traffic_sample\n"
        else
            print_warning "Traffic capture requires root privileges"
        fi
    fi

    # WiFi scanning (if wireless available)
    if command_exists iwlist; then
        echo -e "\n${BLUE}WiFi Network Discovery:${NC}"
        wireless_interface=$(iwconfig 2>/dev/null | grep -o '^[a-zA-Z0-9]*' | head -1)
        if [[ -n "$wireless_interface" ]]; then
            print_info "Scanning for WiFi networks..."
            wifi_results=$(iwlist "$wireless_interface" scan 2>/dev/null | grep "ESSID\|Encryption\|Quality" | head -15)
            echo "$wifi_results"
            discovery_results+="WiFi Networks:\n$wifi_results\n"
        else
            print_info "No wireless interface found"
        fi
    fi

    AUDIT_RESULTS["discovery_results"]="$discovery_results"
}

# Specialized vulnerability scanning function
run_specialized_scans() {
    print_header "SPECIALIZED VULNERABILITY SCANS"

    local_ip=$(ip route get 1.1.1.1 | awk '{print $7; exit}' 2>/dev/null || echo "127.0.0.1")
    scan_results=""

    # Check for web servers and run Nikto if found
    print_info "Checking for local web servers..."
    web_ports=(80 443 8080 8443 8000 3000)
    web_found=false

    for port in "${web_ports[@]}"; do
        if ss -tuln | grep -q ":$port "; then
            web_found=true
            print_status "Found web server on port $port"

            # Run Nikto scan
            if command_exists nikto; then
                print_info "Running Nikto scan on port $port..."
                protocol="http"
                if [[ $port == "443" || $port == "8443" ]]; then
                    protocol="https"
                fi

                nikto_results=$(nikto -h "$protocol://$local_ip:$port" -Tuning x 2>/dev/null | grep -E "(OSVDB|Found|ERROR|WARNING)" | head -20)
                if [[ -n "$nikto_results" ]]; then
                    echo -e "\n${BLUE}Nikto Results for $protocol://$local_ip:$port:${NC}"
                    echo "$nikto_results"
                    scan_results+="Nikto $protocol://$local_ip:$port:\n$nikto_results\n"
                else
                    print_status "No significant vulnerabilities found with Nikto"
                fi
            else
                print_warning "Nikto not found - install with: apt install nikto"
            fi
        fi
    done

    if [[ "$web_found" == false ]]; then
        print_info "No local web servers detected - skipping Nikto scan"
        scan_results+="Web servers: none detected\n"
    fi

    # Check for SMB services and enumerate
    print_info "Checking for SMB services..."
    smb_ports=(139 445)
    smb_found=false

    for port in "${smb_ports[@]}"; do
        if ss -tuln | grep -q ":$port "; then
            smb_found=true
            print_status "Found SMB service on port $port"
        fi
    done

    if [[ "$smb_found" == true ]]; then
        echo -e "\n${BLUE}SMB Enumeration:${NC}"

        # Basic SMB information with smbclient
        if command_exists smbclient; then
            print_info "Gathering SMB shares information..."
            smb_shares=$(smbclient -L "$local_ip" -N 2>/dev/null | grep -E "(Sharename|IPC|ADMIN)" | head -10)
            if [[ -n "$smb_shares" ]]; then
                echo -e "${BLUE}SMB Shares:${NC}"
                echo "$smb_shares"
                scan_results+="SMB Shares:\n$smb_shares\n"
            fi
        fi

        # NetBIOS information
        if command_exists nmblookup; then
            print_info "Gathering NetBIOS information..."
            netbios_info=$(nmblookup -A "$local_ip" 2>/dev/null | grep -E "(Looking|Got reply|GROUP|UNIQUE)" | head -10)
            if [[ -n "$netbios_info" ]]; then
                echo -e "\n${BLUE}NetBIOS Information:${NC}"
                echo "$netbios_info"
                scan_results+="NetBIOS Info:\n$netbios_info\n"
            fi
        fi

        # enum4linux enumeration
        if command_exists enum4linux; then
            print_info "Running enum4linux comprehensive SMB enumeration..."
            echo -e "\n${BLUE}enum4linux Results:${NC}"
            enum4_results=$(enum4linux -a "$local_ip" 2>/dev/null | grep -E "(Domain Name|OS|Server|Users|Shares|Groups)" | head -20)
            if [[ -n "$enum4_results" ]]; then
                echo "$enum4_results"
                scan_results+="enum4linux Results:\n$enum4_results\n"
            else
                print_info "enum4linux completed but no significant results"
            fi
        else
            print_warning "enum4linux not found - install with: apt install enum4linux"
        fi

        # SMB protocol version detection
        if command_exists smbmap; then
            print_info "Checking SMB protocol versions and permissions..."
            smbmap_results=$(smbmap -H "$local_ip" 2>/dev/null | grep -E "(Working on|Disk|READ|WRITE)" | head -10)
            if [[ -n "$smbmap_results" ]]; then
                echo -e "\n${BLUE}SMB Protocol & Permissions:${NC}"
                echo "$smbmap_results"
                scan_results+="SMB Protocol Info:\n$smbmap_results\n"
            fi
        fi

        # Additional SMB security checks
        echo -e "\n${BLUE}SMB Security Assessment:${NC}"

        # Check for SMBv1 (dangerous)
        if command_exists nmap; then
            smb_version=$(nmap -p 445 --script smb-protocols "$local_ip" 2>/dev/null | grep -E "(SMBv1|SMBv2|SMBv3)")
            if [[ -n "$smb_version" ]]; then
                echo "$smb_version"
                if echo "$smb_version" | grep -q "SMBv1"; then
                    print_error "SMBv1 detected - HIGH SECURITY RISK!"
                    scan_results+="SMBv1: DETECTED - HIGH RISK\n"
                else
                    print_status "No SMBv1 detected"
                fi
                scan_results+="SMB Versions: $smb_version\n"
            fi
        fi

        # Check for null session
        null_session=$(smbclient -L "$local_ip" -N 2>&1 | grep -i "anonymous")
        if [[ -n "$null_session" ]]; then
            print_warning "Null session access may be available"
            scan_results+="Null Session: possible\n"
        fi

    else
        print_info "No SMB services detected on standard ports"
        scan_results+="SMB services: none detected\n"
    fi

    # Additional service-specific scans
    echo -e "\n${BLUE}Additional Service Scans:${NC}"

    # SSH banner grabbing and security check
    if ss -tuln | grep -q ":22 "; then
        if command_exists ssh; then
            print_info "Gathering SSH banner information..."
            ssh_banner=$(timeout 5 ssh -o ConnectTimeout=3 "$local_ip" exit 2>&1 | head -3)
            if [[ -n "$ssh_banner" ]]; then
                echo -e "${BLUE}SSH Banner:${NC}"
                echo "$ssh_banner"
                scan_results+="SSH Banner:\n$ssh_banner\n"
            fi
        fi
    fi

    # DNS service enumeration
    if ss -tuln | grep -q ":53 "; then
        print_info "DNS service detected - checking configuration..."
        if command_exists dig; then
            dns_version=$(dig @"$local_ip" version.bind chaos txt 2>/dev/null | grep -E "(VERSION|BIND)")
            if [[ -n "$dns_version" ]]; then
                echo -e "${BLUE}DNS Version:${NC}"
                echo "$dns_version"
                scan_results+="DNS Version:\n$dns_version\n"
            fi
        fi
    fi

    # FTP service enumeration
    if ss -tuln | grep -q ":21 "; then
        print_info "FTP service detected - checking banner..."
        if command_exists nc; then
            ftp_banner=$(timeout 5 nc "$local_ip" 21 2>/dev/null | head -3)
            if [[ -n "$ftp_banner" ]]; then
                echo -e "${BLUE}FTP Banner:${NC}"
                echo "$ftp_banner"
                scan_results+="FTP Banner:\n$ftp_banner\n"

                # Check for anonymous FTP
                anon_ftp=$(timeout 5 ftp -n "$local_ip" <<< "user anonymous anonymous" 2>&1 | grep -i "logged in")
                if [[ -n "$anon_ftp" ]]; then
                    print_warning "Anonymous FTP access may be enabled"
                    scan_results+="Anonymous FTP: possible\n"
                fi
            fi
        fi
    fi

    AUDIT_RESULTS["specialized_scans"]="$scan_results"
}

# Security recommendations
security_recommendations() {
    print_header "SECURITY RECOMMENDATIONS"

    recommendations=""

    # SSH recommendations
    if systemctl is-active --quiet ssh 2>/dev/null; then
        print_warning "SSH is running - consider these hardening steps:"
        echo "  • Change default port (22) to something else"
        echo "  • Disable root login (PermitRootLogin no)"
        echo "  • Use key-based authentication only"
        echo "  • Enable fail2ban for brute force protection"
        recommendations+="SSH: running - needs hardening\n"
    fi

    # Firewall recommendations
    if ! iptables -L | grep -q "Chain INPUT (policy DROP)"; then
        print_warning "Consider implementing a default-deny firewall policy"
        recommendations+="Firewall: no default-deny policy\n"
    fi

    # Update recommendations
    echo -e "\n${BLUE}System Update Check:${NC}"
    if command_exists apt; then
        last_update=$(stat -c %Y /var/lib/apt/lists/* 2>/dev/null | sort -n | tail -1)
        if [[ -n "$last_update" ]]; then
            days_old=$(( ($(date +%s) - last_update) / 86400 ))
            if [[ $days_old -gt 7 ]]; then
                print_warning "Package list is $days_old days old - consider running 'apt update'"
                recommendations+="Updates: $days_old days old\n"
            else
                print_status "Package list is relatively fresh ($days_old days old)"
                recommendations+="Updates: current\n"
            fi
        fi
    fi

    print_info "General recommendations for Kali Linux:"
    echo "  • Only run services when actively needed"
    echo "  • Use strong passwords and key authentication"
    echo "  • Keep system updated with 'apt update && apt upgrade'"
    echo "  • Use VPN when connecting to targets"
    echo "  • Regularly audit listening services"
    echo "  • Consider using full disk encryption"

    AUDIT_RESULTS["recommendations"]="$recommendations"
}

# Export results to JSON
export_json() {
    print_header "EXPORTING JSON REPORT"

    json_file="$OUTPUT_DIR/kali_audit_${HOSTNAME}_${TIMESTAMP}.json"

    print_info "Creating JSON export: $json_file"

    cat > "$json_file" << EOF
{
  "audit_info": {
    "timestamp": "${AUDIT_RESULTS[timestamp]}",
    "hostname": "${AUDIT_RESULTS[hostname]}",
    "user": "${AUDIT_RESULTS[user]}",
    "script_version": "2.0"
  },
  "system_info": {
    "kernel": "${AUDIT_RESULTS[system_kernel]}",
    "distro": "${AUDIT_RESULTS[system_distro]}",
    "uptime": "${AUDIT_RESULTS[system_uptime]}",
    "load_average": "${AUDIT_RESULTS[system_load]}",
    "kali_confirmed": ${AUDIT_RESULTS[kali_confirmed]}
  },
  "network": {
    "interfaces": "${AUDIT_RESULTS[network_interfaces]}",
    "listening_ports": "${AUDIT_RESULTS[listening_ports]}",
    "established_connections": "${AUDIT_RESULTS[established_connections]}",
    "connection_count": ${AUDIT_RESULTS[connection_count]},
    "promiscuous_mode": "${AUDIT_RESULTS[promiscuous_mode]}"
  },
  "security": {
    "firewall_status": "${AUDIT_RESULTS[firewall_status]}",
    "firewall_protection": "${AUDIT_RESULTS[firewall_protection]}",
    "dangerous_ports": "${AUDIT_RESULTS[dangerous_ports]}",
    "suspicious_processes": "${AUDIT_RESULTS[suspicious_processes]}"
  },
  "services": {
    "services_info": "${AUDIT_RESULTS[services_info]}",
    "kali_specific": "${AUDIT_RESULTS[kali_specific]}"
  },
  "scan_results": {
    "nmap_tcp": "${AUDIT_RESULTS[nmap_tcp]}",
    "nmap_udp": "${AUDIT_RESULTS[nmap_udp]}",
    "nmap_services": "${AUDIT_RESULTS[nmap_services]}",
    "discovery_results": "${AUDIT_RESULTS[discovery_results]}",
    "specialized_scans": "${AUDIT_RESULTS[specialized_scans]}"
  },
  "recommendations": "${AUDIT_RESULTS[recommendations]}",
  "summary": {
    "total_warnings": $(echo "${AUDIT_RESULTS[warnings]}" | grep -o "|" | wc -l),
    "total_errors": $(echo "${AUDIT_RESULTS[errors]}" | grep -o "|" | wc -l),
    "total_info": $(echo "${AUDIT_RESULTS[info]}" | grep -o "|" | wc -l)
  }
}
EOF

    print_status "JSON report created: $json_file"
}

# Export results to HTML
export_html() {
    print_header "EXPORTING HTML REPORT"

    html_file="$OUTPUT_DIR/kali_audit_${HOSTNAME}_${TIMESTAMP}.html"

    print_info "Creating HTML export: $html_file"

    cat > "$html_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kali Linux Network Security Audit Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .header p { font-size: 1.2rem; opacity: 0.9; }
        .section {
            background: white;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .section-header {
            background: #2c3e50;
            color: white;
            padding: 15px 20px;
            font-size: 1.3rem;
            font-weight: bold;
        }
        .section-content { padding: 20px; }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .info-card {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 15px;
        }
        .info-card h4 { color: #495057; margin-bottom: 10px; }
        .status { padding: 5px 10px; border-radius: 4px; font-weight: bold; margin: 2px; display: inline-block; }
        .status-good { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .status-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .status-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        pre {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            font-size: 0.9rem;
        }
        .summary {
            display: flex;
            justify-content: space-around;
            text-align: center;
            margin: 20px 0;
        }
        .summary-item {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            flex: 1;
            margin: 0 10px;
        }
        .summary-number { font-size: 2rem; font-weight: bold; color: #667eea; }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            border-top: 1px solid #eee;
        }
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 2rem; }
            .info-grid { grid-template-columns: 1fr; }
            .summary { flex-direction: column; }
            .summary-item { margin: 10px 0; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Kali Linux Security Audit</h1>
            <p>Network Security Assessment Report</p>
            <p>Generated on: TIMESTAMP_PLACEHOLDER for HOST_PLACEHOLDER</p>
        </div>

        <div class="summary">
            <div class="summary-item">
                <div class="summary-number" id="total-checks">-</div>
                <div>Total Checks</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #28a745;" id="good-status">-</div>
                <div>Good Status</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #ffc107;" id="warnings">-</div>
                <div>Warnings</div>
            </div>
            <div class="summary-item">
                <div class="summary-number" style="color: #dc3545;" id="errors">-</div>
                <div>Errors</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">System Information</div>
            <div class="section-content">
                <div class="info-grid">
                    <div class="info-card">
                        <h4>System Details</h4>
                        <p><strong>Hostname:</strong> HOSTNAME_PLACEHOLDER</p>
                        <p><strong>Kernel:</strong> KERNEL_PLACEHOLDER</p>
                        <p><strong>Distribution:</strong> DISTRO_PLACEHOLDER</p>
                        <p><strong>Uptime:</strong> UPTIME_PLACEHOLDER</p>
                    </div>
                    <div class="info-card">
                        <h4>System Load</h4>
                        <p>LOAD_PLACEHOLDER</p>
                        <div class="status status-info">Kali Linux Confirmed</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Network Interfaces & Connections</div>
            <div class="section-content">
                <h4>Active Network Interfaces:</h4>
                <pre>INTERFACES_PLACEHOLDER</pre>
                <h4>Listening Ports:</h4>
                <pre>LISTENING_PORTS_PLACEHOLDER</pre>
                <h4>Established Connections:</h4>
                <p>Total connections: CONNECTION_COUNT_PLACEHOLDER</p>
                <pre>ESTABLISHED_CONNECTIONS_PLACEHOLDER</pre>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Firewall & Security Status</div>
            <div class="section-content">
                <pre>FIREWALL_STATUS_PLACEHOLDER</pre>
                <h4>Security Parameters:</h4>
                <pre>NETWORK_CONFIG_PLACEHOLDER</pre>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Running Services</div>
            <div class="section-content">
                <pre>SERVICES_INFO_PLACEHOLDER</pre>
                <h4>Kali-Specific Services:</h4>
                <pre>KALI_SERVICES_PLACEHOLDER</pre>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Scan Results</div>
            <div class="section-content">
                <h4>Nmap TCP Scan:</h4>
                <pre>NMAP_TCP_PLACEHOLDER</pre>
                <h4>Network Discovery Results:</h4>
                <pre>DISCOVERY_PLACEHOLDER</pre>
                <h4>Specialized Vulnerability Scans:</h4>
                <pre>SPECIALIZED_SCANS_PLACEHOLDER</pre>
            </div>
        </div>

        <div class="section">
            <div class="section-header">Security Recommendations</div>
            <div class="section-content">
                <div class="status status-warning">Review Required</div>
                <pre>RECOMMENDATIONS_PLACEHOLDER</pre>
            </div>
        </div>

        <div class="footer">
            <p>Report generated by Kali Linux Network Security Audit Script v2.0</p>
            <p>For more information, visit the project repository</p>
        </div>
    </div>

    <script>
        // Populate summary numbers
        document.getElementById('total-checks').textContent = '12';
        document.getElementById('good-status').textContent = 'GOOD_COUNT';
        document.getElementById('warnings').textContent = 'WARNING_COUNT';
        document.getElementById('errors').textContent = 'ERROR_COUNT';
    </script>
</body>
</html>
EOF

    # Replace placeholders with actual data
    sed -i "s/TIMESTAMP_PLACEHOLDER/${AUDIT_RESULTS[timestamp]}/g" "$html_file"
    sed -i "s/HOST_PLACEHOLDER/${AUDIT_RESULTS[hostname]}/g" "$html_file"
    sed -i "s/HOSTNAME_PLACEHOLDER/${AUDIT_RESULTS[hostname]}/g" "$html_file"
    sed -i "s/KERNEL_PLACEHOLDER/${AUDIT_RESULTS[system_kernel]}/g" "$html_file"
    sed -i "s/DISTRO_PLACEHOLDER/${AUDIT_RESULTS[system_distro]}/g" "$html_file"
    sed -i "s/UPTIME_PLACEHOLDER/${AUDIT_RESULTS[system_uptime]}/g" "$html_file"
    sed -i "s/LOAD_PLACEHOLDER/${AUDIT_RESULTS[system_load]}/g" "$html_file"
    sed -i "s/CONNECTION_COUNT_PLACEHOLDER/${AUDIT_RESULTS[connection_count]}/g" "$html_file"

    # Replace multi-line content (escape special characters)
    python3 << EOF
import re
import sys

# Read the HTML file
with open('$html_file', 'r') as f:
    content = f.read()

# Replace placeholders with actual data (escape HTML special characters)
def escape_html(text):
    text = str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    return text.replace('\n', '<br>').replace('\t', '&nbsp;&nbsp;&nbsp;&nbsp;')

replacements = {
    'INTERFACES_PLACEHOLDER': escape_html('${AUDIT_RESULTS[network_interfaces]}'),
    'LISTENING_PORTS_PLACEHOLDER': escape_html('${AUDIT_RESULTS[listening_ports]}'),
    'ESTABLISHED_CONNECTIONS_PLACEHOLDER': escape_html('${AUDIT_RESULTS[established_connections]}'),
    'FIREWALL_STATUS_PLACEHOLDER': escape_html('${AUDIT_RESULTS[firewall_status]}'),
    'NETWORK_CONFIG_PLACEHOLDER': escape_html('${AUDIT_RESULTS[network_config]}'),
    'SERVICES_INFO_PLACEHOLDER': escape_html('${AUDIT_RESULTS[services_info]}'),
    'KALI_SERVICES_PLACEHOLDER': escape_html('${AUDIT_RESULTS[kali_specific]}'),
    'NMAP_TCP_PLACEHOLDER': escape_html('${AUDIT_RESULTS[nmap_tcp]}'),
    'DISCOVERY_PLACEHOLDER': escape_html('${AUDIT_RESULTS[discovery_results]}'),
    'SPECIALIZED_SCANS_PLACEHOLDER': escape_html('${AUDIT_RESULTS[specialized_scans]}'),
    'RECOMMENDATIONS_PLACEHOLDER': escape_html('${AUDIT_RESULTS[recommendations]}')
}

for placeholder, replacement in replacements.items():
    content = content.replace(placeholder, replacement)

# Write back the modified content
with open('$html_file', 'w') as f:
    f.write(content)
EOF

    print_status "HTML report created: $html_file"
    print_info "Open in browser: file://$html_file"
}

# Parse arguments and run main function
parse_args "$@"
setup_output_dir
main

echo -e "\n${GREEN}Network security audit completed!${NC}"

if [[ "$EXPORT_JSON" == true ]] || [[ "$EXPORT_HTML" == true ]]; then
    echo -e "${BLUE}Reports saved in: $OUTPUT_DIR${NC}"
fi

echo -e "${BLUE}For additional analysis, consider running:${NC}"
echo "  • lynis audit system (comprehensive security audit)"
echo "  • rkhunter --check (rootkit scanner)"
echo "  • chkrootkit (alternative rootkit checker)"
echo "  • nikto -h http://target (web vulnerability scanner)"
echo "  • enum4linux target (SMB enumeration)"
echo "  • smbmap -H target (SMB share mapping)"
echo "  • nbtscan target (NetBIOS scanner)"
echo ""
