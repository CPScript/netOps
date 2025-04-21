#!/bin/bash

set -e
VERSION="1.0.0"

CONFIG_DIR="/etc/netops"
LOG_DIR="/var/log/netops"
NFT_DIR="/etc/nftables.d"
PCAP_DIR="/var/netops/pcap"
MAX_LOG_SIZE="50M"
INTERFACES=()
DEFAULT_TTL=64
CUSTOM_TTL_MAP=()
ENABLE_MITM=0
ENABLE_STEALTH=0
SCAN_INTERVAL=300
AUDIT_LEVEL=3


init_directories() {
    mkdir -p $CONFIG_DIR $LOG_DIR $NFT_DIR $PCAP_DIR
    chmod 750 $CONFIG_DIR $LOG_DIR $NFT_DIR $PCAP_DIR
}

detect_interfaces() {
    local IFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -v "lo")
    INTERFACES=($IFACES)
    log_info "Detected interfaces: ${INTERFACES[*]}"
}

validate_environment() {
    local FAILED=0
    
    for cmd in nft ip tcpdump awk grep sed; do
        if ! command -v $cmd &> /dev/null; then
            log_error "Required binary not found: $cmd"
            FAILED=1
        fi
    done
    
    for mod in nf_tables nf_nat nf_conntrack; do
        if ! lsmod | grep -q $mod; then
            log_warning "Kernel module not loaded: $mod"
        fi
    done
    
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    return $FAILED
}

configure_ttl_manipulation() {
    cat > $NFT_DIR/netops-ttl.nft << EOF
table inet netops {
    chain mangle_prerouting {
        type filter hook prerouting priority -150; policy accept;
        ip ttl set $DEFAULT_TTL
        ip6 hoplimit set $DEFAULT_TTL
    }
    
    chain mangle_postrouting {
        type filter hook postrouting priority -150; policy accept;
        ip ttl set $DEFAULT_TTL
        ip6 hoplimit set $DEFAULT_TTL
    }
    
    chain netops_logging {
        type filter hook prerouting priority -200; policy accept;
        meta nftrace set 1
    }
}
EOF

    if [[ ${#CUSTOM_TTL_MAP[@]} -gt 0 ]]; then
        for mapping in "${CUSTOM_TTL_MAP[@]}"; do
            IFS=':' read -r subnet ttl <<< "$mapping"
            echo "    ip saddr $subnet ip ttl set $ttl" >> $NFT_DIR/netops-ttl.nft
            echo "    ip daddr $subnet ip ttl set $ttl" >> $NFT_DIR/netops-ttl.nft
        done
    fi
    
    if nft -f $NFT_DIR/netops-ttl.nft; then
        log_info "TTL manipulation configured successfully"
    else
        log_error "Failed to apply TTL manipulation rules"
        return 1
    fi
    
    return 0
}

configure_stealth_mode() {
    if [[ $ENABLE_STEALTH -eq 1 ]]; then
        cat > $NFT_DIR/netops-stealth.nft << EOF
table inet netops_stealth {
    chain input_stealth {
        type filter hook input priority -150; policy accept;
        tcp flags syn tcp option maxseg size set 1452
        icmp type echo-request drop
        tcp dport 22 accept
        tcp dport 80 accept
        tcp dport 443 accept
        udp dport 53 accept
        meta pkttype broadcast accept
        meta pkttype multicast accept
        ct state established,related accept
        ct state invalid drop
        limit rate 10/minute burst 5 packets log prefix "STEALTH-DROP: " flags all
        drop
    }
}
EOF
        nft -f $NFT_DIR/netops-stealth.nft
        log_info "Stealth mode enabled"
    else
        nft delete table inet netops_stealth 2>/dev/null || true
        log_info "Stealth mode disabled"
    fi
}

setup_mitm_capabilities() {
    if [[ $ENABLE_MITM -eq 1 ]]; then
        cat > $NFT_DIR/netops-mitm.nft << EOF
table inet netops_mitm {
    chain forward_mitm {
        type filter hook forward priority -150; policy accept;
        ip protocol tcp counter
        ip protocol tcp tcp flags syn counter packets 0 bytes 0 log prefix "MITM-SYN: "
        # Enable packet forwarding
        meta nfproto ipv4 counter accept
    }
    
    chain nat_mitm {
        type nat hook prerouting priority -150; policy accept;
        # Redirect specific ports for interception
        tcp dport { 80, 443 } counter redirect to :8080
    }
}
EOF
        nft -f $NFT_DIR/netops-mitm.nft
        
        echo 1 > /proc/sys/net/ipv4/ip_forward
        
        log_info "MITM capabilities enabled"
    else
        nft delete table inet netops_mitm 2>/dev/null || true
        log_info "MITM capabilities disabled"
    fi
}

execute_payload_injection() {
    local TARGET=$1
    local PAYLOAD=$2
    local PORT=${3:-80}
    
    if [[ -z "$TARGET" || -z "$PAYLOAD" ]]; then
        log_error "Target and payload are required for injection"
        return 1
    fi
    
    cat > $NFT_DIR/netops-inject-temp.nft << EOF
table inet netops_inject {
    chain inject_payload {
        type filter hook forward priority -100; policy accept;
        ip daddr $TARGET tcp dport $PORT tcp payload set $PAYLOAD
    }
}
EOF
    
    nft -f $NFT_DIR/netops-inject-temp.nft
    log_info "Payload injection configured for $TARGET:$PORT"
    
    (sleep 60 && nft delete table inet netops_inject && log_info "Payload injection removed") &
    
    return 0
}

create_covert_channel() {
    local TECHNIQUE=$1
    local ENDPOINT=$2
    
    case $TECHNIQUE in
        "icmp")
            modprobe ip_gre 2>/dev/null || true
            ip tunnel add tun0 mode gre remote $ENDPOINT local $(get_primary_ip) ttl 255
            ip link set tun0 up
            ip addr add 10.10.10.1/30 dev tun0
            
            cat > $NFT_DIR/netops-covert.nft << EOF
table inet netops_covert {
    chain covert_channel {
        type filter hook forward priority -100; policy accept;
        ip protocol icmp counter packets 0 bytes 0
        icmp type echo-request accept
        icmp type echo-reply accept
    }
}
EOF
            nft -f $NFT_DIR/netops-covert.nft
            log_info "ICMP covert channel established to $ENDPOINT"
            ;;
            
        "dns")
            cat > $NFT_DIR/netops-covert.nft << EOF
table inet netops_covert {
    chain covert_channel {
        type filter hook forward priority -100; policy accept;
        udp dport 53 counter packets 0 bytes 0
    }
}
EOF
            nft -f $NFT_DIR/netops-covert.nft
            log_info "DNS covert channel prepared to $ENDPOINT"
            ;;
            
        *)
            log_error "Unknown covert channel technique: $TECHNIQUE"
            return 1
            ;;
    esac
    
    return 0
}

exploit_vulnerable_service() {
    local TARGET=$1
    local SERVICE=$2
    local PORT=$3
    local TECHNIQUE=${4:-"default"}
    
    if [[ -z "$TARGET" || -z "$SERVICE" || -z "$PORT" ]]; then
        log_error "Target, service and port are required for exploitation"
        return 1
    fi
    
    log_info "Attempting to exploit $SERVICE on $TARGET:$PORT using $TECHNIQUE technique"
    
    create_direct_bypass $TARGET $PORT
    
    case $SERVICE in
        "upnp")
            nmap -p $PORT --script upnp-info $TARGET -oN $LOG_DIR/exploit-upnp-$TARGET.log
            log_info "UPnP exploitation results saved to $LOG_DIR/exploit-upnp-$TARGET.log"
            ;;
            
        "smb")
            nmap -p $PORT --script smb-vuln* $TARGET -oN $LOG_DIR/exploit-smb-$TARGET.log
            log_info "SMB exploitation results saved to $LOG_DIR/exploit-smb-$TARGET.log"
            ;;
            
        "router")
            nmap -p $PORT --script http-default-accounts $TARGET -oN $LOG_DIR/exploit-router-$TARGET.log
            log_info "Router exploitation results saved to $LOG_DIR/exploit-router-$TARGET.log"
            ;;
            
        *)
            log_warning "No specific exploitation technique available for $SERVICE"
            return 1
            ;;
    esac
    
    remove_direct_bypass $TARGET $PORT
    
    return 0
}


scan_network_topology() {
    local NETWORK=${1:-"auto"}
    local SCAN_TYPE=${2:-"passive"}
    
    if [[ "$NETWORK" == "auto" ]]; then
        NETWORK=$(ip route | grep -v default | grep -v 'linkdown' | head -1 | awk '{print $1}')
    fi
    
    log_info "Scanning network topology for $NETWORK (type: $SCAN_TYPE)"
    
    local SCAN_DIR="$LOG_DIR/netscan-$(date +%Y%m%d-%H%M%S)"
    mkdir -p $SCAN_DIR
    
    case $SCAN_TYPE in
        "passive")
            timeout 30 tcpdump -i $(get_primary_interface) -nn -e -c 1000 arp 2>/dev/null > $SCAN_DIR/arp-passive.pcap
            tcpdump -r $SCAN_DIR/arp-passive.pcap -n -e | grep "ARP" | awk '{print $2, $4, $8}' | sort | uniq > $SCAN_DIR/network-map.txt
            ;;
            
        "active")
            ip -4 addr show | grep inet | grep -v "127.0.0.1" | awk '{print $2}' | while read -r localnet; do
                nmap -sn $localnet -oN $SCAN_DIR/nmap-$localnet.log
            done
            
            grep "Nmap scan report" $SCAN_DIR/nmap-*.log | awk '{print $5, $6}' > $SCAN_DIR/network-map.txt
            ;;
            
        "deep")
            nmap -sV -O --osscan-guess $NETWORK -oX $SCAN_DIR/nmap-deep.xml
            grep -A 10 "host " $SCAN_DIR/nmap-deep.xml | grep -E "addr|service " > $SCAN_DIR/network-map.txt
            ;;
            
        *)
            log_error "Unknown scan type: $SCAN_TYPE"
            return 1
            ;;
    esac
    
    log_info "Network topology scan complete: $SCAN_DIR/network-map.txt"
    
    analyze_network_vulnerabilities $SCAN_DIR/network-map.txt > $SCAN_DIR/vulnerabilities.txt
    
    return 0
}

detect_network_bottlenecks() {
    local INTERFACE=${1:-$(get_primary_interface)}
    local DURATION=${2:-60}
    
    log_info "Detecting network bottlenecks on $INTERFACE ($DURATION seconds)"
    
    tcpdump -i $INTERFACE -s 0 -w $PCAP_DIR/bottleneck-$(date +%Y%m%d-%H%M%S).pcap -c 10000 &
    local TCPDUMP_PID=$!
    
    STATS_FILE=$LOG_DIR/interface-stats-$(date +%Y%m%d-%H%M%S).log
    
    log_info "Collecting interface statistics for $DURATION seconds..."
    for ((i=1; i<=$DURATION; i++)); do
        echo "=== Sample $i ===" >> $STATS_FILE
        ip -s link show $INTERFACE >> $STATS_FILE
        sleep 1
    done
    
    kill $TCPDUMP_PID 2>/dev/null || true
    
    analyze_interface_statistics $STATS_FILE
    
    return 0
}

get_primary_interface() {
    ip route get 8.8.8.8 | awk '{print $5; exit}'
}

get_primary_ip() {
    ip -4 addr show $(get_primary_interface) | grep -oP 'inet \K[\d.]+'
}

analyze_network_vulnerabilities() {
    local MAPFILE=$1
    
    if [[ ! -f "$MAPFILE" ]]; then
        log_error "Network map file not found: $MAPFILE"
        return 1
    fi
    
    log_info "Analyzing network for potential vulnerabilities"
    
    echo "=== OPEN PORTS ANALYSIS ===" 
    grep -E "port [0-9]+" $MAPFILE | sort | uniq -c | sort -nr
    
    echo "=== GATEWAY ANALYSIS ==="
    ip route | grep default
    
    echo "=== VULNERABLE DEVICE SIGNATURES ==="
    grep -i -E "router|gateway|modem|switch|camera|dvr|iot" $MAPFILE
    
    return 0
}

create_direct_bypass() {
    local TARGET=$1
    local PORT=$2
    
    ip route add $TARGET/32 via $(ip route | grep default | head -1 | awk '{print $3}') dev $(get_primary_interface)
    
    cat > $NFT_DIR/netops-direct-$TARGET-$PORT.nft << EOF
table inet netops_direct {
    chain direct_bypass {
        type filter hook forward priority 0; policy accept;
        ip daddr $TARGET tcp dport $PORT counter accept
        ip saddr $TARGET tcp sport $PORT counter accept
    }
}
EOF
    
    nft -f $NFT_DIR/netops-direct-$TARGET-$PORT.nft
    log_info "Direct bypass created for $TARGET:$PORT"
    
    return 0
}

remove_direct_bypass() {
    local TARGET=$1
    local PORT=$2
    
    ip route del $TARGET/32 2>/dev/null || true
    
    nft delete table inet netops_direct 2>/dev/null || true
    rm -f $NFT_DIR/netops-direct-$TARGET-$PORT.nft
    
    log_info "Direct bypass removed for $TARGET:$PORT"
    
    return 0
}

audit_network_configuration() {
    local AUDIT_FILE="$LOG_DIR/audit-$(date +%Y%m%d-%H%M%S).log"
    
    log_info "Performing network configuration audit (level: $AUDIT_LEVEL)"
    
    echo "=== NETWORK AUDIT $(date) ===" > $AUDIT_FILE
    echo "Audit Level: $AUDIT_LEVEL" >> $AUDIT_FILE
    echo "" >> $AUDIT_FILE
    
    echo "=== NETWORK INTERFACES ===" >> $AUDIT_FILE
    ip addr show >> $AUDIT_FILE
    echo "" >> $AUDIT_FILE
    
    echo "=== ROUTING TABLE ===" >> $AUDIT_FILE
    ip route show >> $AUDIT_FILE
    echo "" >> $AUDIT_FILE
    
    if [[ $AUDIT_LEVEL -ge 2 ]]; then
        echo "=== NFTABLES RULES ===" >> $AUDIT_FILE
        nft list ruleset >> $AUDIT_FILE
        echo "" >> $AUDIT_FILE
        
        echo "=== NETWORK STATISTICS ===" >> $AUDIT_FILE
        ip -s link >> $AUDIT_FILE
        echo "" >> $AUDIT_FILE
        
        echo "=== CONNECTION TRACKING ===" >> $AUDIT_FILE
        cat /proc/net/nf_conntrack | head -100 >> $AUDIT_FILE
        echo "" >> $AUDIT_FILE
    fi
    
    if [[ $AUDIT_LEVEL -ge 3 ]]; then
        echo "=== NETWORK SOCKETS ===" >> $AUDIT_FILE
        ss -tuapn >> $AUDIT_FILE
        echo "" >> $AUDIT_FILE
        
        echo "=== INTERFACE PARAMETERS ===" >> $AUDIT_FILE
        for iface in "${INTERFACES[@]}"; do
            echo "--- $iface ---" >> $AUDIT_FILE
            ethtool $iface 2>/dev/null >> $AUDIT_FILE || echo "ethtool not available" >> $AUDIT_FILE
            echo "" >> $AUDIT_FILE
        done
        
        echo "=== SYSTEM NETWORK PARAMETERS ===" >> $AUDIT_FILE
        sysctl -a | grep -E 'net\.(ipv4|ipv6|core)' >> $AUDIT_FILE
        echo "" >> $AUDIT_FILE
    fi
    
    log_info "Audit completed: $AUDIT_FILE"
    
    analyze_audit_security $AUDIT_FILE > "${AUDIT_FILE%.log}-security.log"
    
    return 0
}

analyze_audit_security() {
    local AUDIT_FILE=$1
    
    if [[ ! -f "$AUDIT_FILE" ]]; then
        log_error "Audit file not found: $AUDIT_FILE"
        return 1
    fi
    
    echo "=== SECURITY ANALYSIS OF AUDIT $(date) ==="
    
    echo "=== IP FORWARDING ==="
    grep "ip_forward" $AUDIT_FILE
    
    echo "=== OPEN PORTS ==="
    grep "LISTEN" $AUDIT_FILE
    
    echo "=== SUSPICIOUS CONNECTIONS ==="
    grep -E "(ESTABLISHED|SYN-SENT)" $AUDIT_FILE | grep -v "127.0.0.1"
    
    echo "=== WEAK NETWORK PARAMETERS ==="
    grep -E "rp_filter|log_martians|accept_redirects|accept_source_route" $AUDIT_FILE
    
    return 0
}

audit_traffic_patterns() {
    local INTERFACE=${1:-$(get_primary_interface)}
    local DURATION=${2:-300}
    
    log_info "Auditing traffic patterns on $INTERFACE for $DURATION seconds"
    
    local CAPTURE_FILE="$PCAP_DIR/traffic-audit-$(date +%Y%m%d-%H%M%S).pcap"
    tcpdump -i $INTERFACE -s 0 -w $CAPTURE_FILE &
    local TCPDUMP_PID=$!
    
    sleep $DURATION
    
    kill $TCPDUMP_PID 2>/dev/null || true
    
    local ANALYSIS_FILE="${CAPTURE_FILE%.pcap}-analysis.txt"
    
    echo "=== TRAFFIC PATTERN ANALYSIS ===" > $ANALYSIS_FILE
    echo "Capture Duration: $DURATION seconds" >> $ANALYSIS_FILE
    echo "Interface: $INTERFACE" >> $ANALYSIS_FILE
    echo "" >> $ANALYSIS_FILE
    
    echo "=== PROTOCOL DISTRIBUTION ===" >> $ANALYSIS_FILE
    tcpdump -r $CAPTURE_FILE -nn -q | awk '{print $2}' | sort | uniq -c | sort -nr >> $ANALYSIS_FILE
    echo "" >> $ANALYSIS_FILE
    
    echo "=== TOP SOURCE IPS ===" >> $ANALYSIS_FILE
    tcpdump -r $CAPTURE_FILE -nn | awk '{print $3}' | awk -F. '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -nr | head -20 >> $ANALYSIS_FILE
    echo "" >> $ANALYSIS_FILE
    
    echo "=== TOP DESTINATION IPS ===" >> $ANALYSIS_FILE
    tcpdump -r $CAPTURE_FILE -nn | awk '{print $5}' | awk -F. '{print $1"."$2"."$3"."$4}' | sort | uniq -c | sort -nr | head -20 >> $ANALYSIS_FILE
    echo "" >> $ANALYSIS_FILE
    
    echo "=== TOP DESTINATION PORTS ===" >> $ANALYSIS_FILE
    tcpdump -r $CAPTURE_FILE -nn 'tcp or udp' | awk '{print $5}' | awk -F. '{print $5}' | sort | uniq -c | sort -nr | head -20 >> $ANALYSIS_FILE
    
    log_info "Traffic audit analysis complete: $ANALYSIS_FILE"
    
    return 0
}


setup_logging() {
    mkdir -p $LOG_DIR
    
    cat > /etc/logrotate.d/netops << EOF
$LOG_DIR/*.log {
    size $MAX_LOG_SIZE
    rotate 5
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
    
    MAIN_LOG="$LOG_DIR/netops.log"
    touch $MAIN_LOG
    chmod 0640 $MAIN_LOG
    
    log_info "Logging initialized: $MAIN_LOG"
    
    return 0
}

log_info() {
    local MSG="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $MSG" >> $LOG_DIR/netops.log
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo "[INFO] $MSG"
    fi
}

log_warning() {
    local MSG="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $MSG" >> $LOG_DIR/netops.log
    if [[ "$VERBOSE" -eq 1 ]]; then
        echo "[WARN] $MSG" >&2
    fi
}

log_error() {
    local MSG="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $MSG" >> $LOG_DIR/netops.log
    if [[ "$VERBOSE" -ne 0 ]]; then
        echo "[ERROR] $MSG" >&2
    fi
}

setup_packet_logging() {
    local INTERFACE=${1:-$(get_primary_interface)}
    local FILTER=${2:-""}
    
    cat > $NFT_DIR/netops-logging.nft << EOF
table inet netops_logging {
    chain logging_chain {
        type filter hook forward priority -200; policy accept;
        meta nftrace set 1
        log prefix "NETOPS-PACKET: "
    }
}
EOF
    
    if [[ -n "$FILTER" ]]; then
        sed -i "/meta nftrace/i\\        $FILTER" $NFT_DIR/netops-logging.nft
    fi
    
    nft -f $NFT_DIR/netops-logging.nft
    
    PCAP_FILE="$PCAP_DIR/netops-$(date +%Y%m%d-%H%M%S).pcap"
    tcpdump -i $INTERFACE -s 0 -w $PCAP_FILE -G 3600 &
    echo $! > /var/run/netops-tcpdump.pid
    
    log_info "Packet logging enabled on $INTERFACE (PID: $(cat /var/run/netops-tcpdump.pid))"
    
    return 0
}

stop_packet_logging() {
    if [[ -f /var/run/netops-tcpdump.pid ]]; then
        kill $(cat /var/run/netops-tcpdump.pid) 2>/dev/null || true
        rm -f /var/run/netops-tcpdump.pid
    fi
    
    nft delete table inet netops_logging 2>/dev/null || true
    
    log_info "Packet logging disabled"
    
    return 0
}

analyze_logs() {
    local LOG_PATH=${1:-"$LOG_DIR/netops.log"}
    local OUTPUT_FILE="$LOG_DIR/log-analysis-$(date +%Y%m%d-%H%M%S).txt"
    
    log_info "Analyzing logs: $LOG_PATH"
    
    echo "=== LOG ANALYSIS $(date) ===" > $OUTPUT_FILE
    echo "Source log: $LOG_PATH" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    echo "=== ERROR FREQUENCY ===" >> $OUTPUT_FILE
    grep ERROR $LOG_PATH | awk '{print $4}' | sort | uniq -c | sort -nr >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    echo "=== WARNING FREQUENCY ===" >> $OUTPUT_FILE
    grep WARN $LOG_PATH | awk '{print $4}' | sort | uniq -c | sort -nr >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    echo "=== OPERATION FREQUENCY ===" >> $OUTPUT_FILE
    grep -E 'enabled|disabled|configured|completed' $LOG_PATH | awk '{print $4, $5}' | sort | uniq -c | sort -nr >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    echo "=== IP ADDRESSES MENTIONED ===" >> $OUTPUT_FILE
    grep -E -o '([0-9]{1,3}\.){3}[0-9]{1,3}' $LOG_PATH | sort | uniq -c | sort -nr >> $OUTPUT_FILE
    
    log_info "Log analysis completed: $OUTPUT_FILE"
    
    return 0
}

analyze_interface_statistics() {
    local STATS_FILE=$1
    local OUTPUT_FILE="${STATS_FILE%.log}-analysis.txt"
    
    log_info "Analyzing interface statistics from $STATS_FILE"
    
    echo "=== INTERFACE STATISTICS ANALYSIS ===" > $OUTPUT_FILE
    echo "Source: $STATS_FILE" >> $OUTPUT_FILE
    echo "Date: $(date)" >> $OUTPUT_FILE
    echo "" >> $OUTPUT_FILE
    
    grep -A 2 "Sample" $STATS_FILE | grep -E "RX|TX" | grep bytes > $OUTPUT_FILE.tmp
    
    echo "=== THROUGHPUT ANALYSIS ===" >> $OUTPUT_FILE
    
    echo "--- RX Throughput ---" >> $OUTPUT_FILE
    prev_bytes=0
    grep "RX:" $OUTPUT_FILE.tmp | awk '{print $2}' | while read -r bytes; do
        if [[ $prev_bytes -ne 0 ]]; then
            throughput=$((bytes - prev_bytes))
            echo "$throughput bytes/sec"
        fi
        prev_bytes=$bytes
    done | tail -n +2 >> $OUTPUT_FILE
    
    echo "--- TX Throughput ---" >> $OUTPUT_FILE
    prev_bytes=0
    grep "TX:" $OUTPUT_FILE.tmp | awk '{print $2}' | while read -r bytes; do
        if [[ $prev_bytes -ne 0 ]]; then
            throughput=$((bytes - prev_bytes))
            echo "$throughput bytes/sec"
        fi
        prev_bytes=$bytes
    done | tail -n +2 >> $OUTPUT_FILE
    
    echo "=== ERROR ANALYSIS ===" >> $OUTPUT_FILE
    grep -E "dropped|errors|overrun" $STATS_FILE >> $OUTPUT_FILE
    
    rm -f $OUTPUT_FILE.tmp
    
    log_info "Interface statistics analysis complete: $OUTPUT_FILE"
    
    return 0
}

setup_tunnel() {
    local REMOTE_IP=$1
    local TUNNEL_TYPE=${2:-"gre"}
    local LOCAL_IP=$(get_primary_ip)
    
    if [[ -z "$REMOTE_IP" ]]; then
        log_error "Remote IP is required for tunnel setup"
        return 1
    fi
    
    log_info "Setting up $TUNNEL_TYPE tunnel to $REMOTE_IP"
    
    case $TUNNEL_TYPE in
        "gre")
            modprobe ip_gre 2>/dev/null || true
            ip tunnel add tun0 mode gre remote $REMOTE_IP local $LOCAL_IP ttl 255
            ip link set tun0 up
            ip addr add 10.10.10.1/30 dev tun0
            ;;
            
        "ipip")
            modprobe ipip 2>/dev/null || true
            ip tunnel add tun0 mode ipip remote $REMOTE_IP local $LOCAL_IP ttl 255
            ip link set tun0 up
            ip addr add 10.10.10.1/30 dev tun0
            ;;
            
        "wireguard")
            if ! command -v wg &> /dev/null; then
                log_error "WireGuard not available"
                return 1
            fi
            
            local PRIVATE_KEY=$(wg genkey)
            local PUBLIC_KEY=$(echo $PRIVATE_KEY | wg pubkey)
            
            ip link add dev wg0 type wireguard
            ip addr add 10.10.10.1/24 dev wg0
            
            echo $PRIVATE_KEY | wg set wg0 private-key /proc/self/fd/0
            wg set wg0 listen-port 51820
            ip link set wg0 up
            
            log_info "WireGuard configured. Public key: $PUBLIC_KEY"
            log_info "Add peer manually: wg set wg0 peer REMOTE_PUBLIC_KEY allowed-ips 10.10.10.2/32 endpoint ${REMOTE_IP}:51820"
            ;;
            
        *)
            log_error "Unknown tunnel type: $TUNNEL_TYPE"
            return 1
            ;;
    esac
    
    log_info "Tunnel setup complete. Interface: ${TUNNEL_TYPE}0"
    
    return 0
}

destroy_tunnel() {
    local TUNNEL_TYPE=${1:-"gre"}
    
    log_info "Destroying $TUNNEL_TYPE tunnel"
    
    case $TUNNEL_TYPE in
        "gre"|"ipip")
            ip tunnel del tun0 2>/dev/null || true
            ;;
            
        "wireguard")
            ip link delete dev wg0 2>/dev/null || true
            ;;
            
        *)
            log_error "Unknown tunnel type: $TUNNEL_TYPE"
            return 1
            ;;
    esac
    
    log_info "Tunnel destroyed successfully"
    
    return 0
}

setup_traffic_shaping() {
    local INTERFACE=${1:-$(get_primary_interface)}
    local DOWNLOAD_LIMIT=${2:-"10mbit"}
    local UPLOAD_LIMIT=${3:-"5mbit"}
    
    log_info "Setting up traffic shaping on $INTERFACE (DL: $DOWNLOAD_LIMIT, UL: $UPLOAD_LIMIT)"
    
    tc qdisc del dev $INTERFACE root 2>/dev/null || true
    
    tc qdisc add dev $INTERFACE root handle 1: htb default 30
    
    tc class add dev $INTERFACE parent 1: classid 1:1 htb rate $DOWNLOAD_LIMIT
    
    tc class add dev $INTERFACE parent 1:1 classid 1:10 htb rate $(($(echo $DOWNLOAD_LIMIT | sed 's/mbit//') * 7 / 10))mbit ceil $DOWNLOAD_LIMIT prio 1
    tc class add dev $INTERFACE parent 1:1 classid 1:20 htb rate $(($(echo $DOWNLOAD_LIMIT | sed 's/mbit//') * 2 / 10))mbit ceil $DOWNLOAD_LIMIT prio 2
    tc class add dev $INTERFACE parent 1:1 classid 1:30 htb rate $(($(echo $DOWNLOAD_LIMIT | sed 's/mbit//') * 1 / 10))mbit ceil $DOWNLOAD_LIMIT prio 3
    
    tc filter add dev $INTERFACE parent 1: protocol ip prio 1 u32 match ip dport 80 0xffff flowid 1:10
    tc filter add dev $INTERFACE parent 1: protocol ip prio 1 u32 match ip dport 443 0xffff flowid 1:10
    tc filter add dev $INTERFACE parent 1: protocol ip prio 2 u32 match ip dport 22 0xffff flowid 1:20
    
    log_info "Traffic shaping configured on $INTERFACE"
    
    return 0
}

print_usage() {
    cat << EOF
NetOps Framework $VERSION
Usage: $0 [options] command [params]

Options:
  -v, --verbose             Enable verbose output
  -h, --help                Display this help
  -c, --config <file>       Use specific configuration file
  -i, --interface <iface>   Specify network interface

Commands:
  init                      Initialize the framework
  ttl <value>               Configure TTL manipulation (default: 64)
  map-ttl <subnet:ttl>      Map subnet to specific TTL value
  scan [network] [type]     Scan network (passive|active|deep)
  audit [level]             Audit network configuration (1-3)
  log [interface] [filter]  Enable packet logging
  tunnel <remote> [type]    Create tunnel to remote host
  mitm <enable|disable>     Enable/disable MITM capabilities
  stealth <enable|disable>  Enable/disable stealth mode
  exploit <target> <service> <port> [technique]
                            Exploit vulnerable service
  traffic <interface> [dl] [ul]
                            Configure traffic shaping
  help                      Display this help

Examples:
  $0 init
  $0 ttl 128
  $0 map-ttl 192.168.1.0/24:32
  $0 scan 192.168.0.0/24 active
  $0 audit 3
  $0 log eth0 "tcp port 80 or tcp port 443"
  $0 tunnel 192.168.100.1 wireguard
  $0 mitm enable
  $0 stealth enable
  $0 exploit 192.168.1.1 upnp 5000
  $0 traffic eth0 20mbit 10mbit
EOF
}

parse_arguments() {
    VERBOSE=0
    CONFIG_FILE=""
    
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -i|--interface)
                INTERFACE="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done
    
    if [[ $# -eq 0 ]]; then
        print_usage
        exit 1
    fi
    
    COMMAND="$1"
    shift
    
    case "$COMMAND" in
        init)
            init_framework
            ;;
        ttl)
            if [[ $# -gt 0 ]]; then
                DEFAULT_TTL="$1"
            fi
            configure_ttl_manipulation
            ;;
        map-ttl)
            if [[ $# -gt 0 ]]; then
                CUSTOM_TTL_MAP+=("$1")
            else
                log_error "Subnet:TTL mapping required"
                exit 1
            fi
            configure_ttl_manipulation
            ;;
        scan)
            NETWORK=""
            SCAN_TYPE="passive"
            if [[ $# -gt 0 ]]; then
                NETWORK="$1"
            fi
            if [[ $# -gt 1 ]]; then
                SCAN_TYPE="$2"
            fi
            scan_network_topology "$NETWORK" "$SCAN_TYPE"
            ;;
        audit)
            if [[ $# -gt 0 ]]; then
                AUDIT_LEVEL="$1"
            fi
            audit_network_configuration
            ;;
        log)
            INTERFACE=""
            FILTER=""
            if [[ $# -gt 0 ]]; then
                INTERFACE="$1"
            fi
            if [[ $# -gt 1 ]]; then
                FILTER="$2"
            fi
            setup_packet_logging "$INTERFACE" "$FILTER"
            ;;
        nolog)
            stop_packet_logging
            ;;
        tunnel)
            if [[ $# -lt 1 ]]; then
                log_error "Remote IP required for tunnel"
                exit 1
            fi
            REMOTE_IP="$1"
            TUNNEL_TYPE="gre"
            if [[ $# -gt 1 ]]; then
                TUNNEL_TYPE="$2"
            fi
            setup_tunnel "$REMOTE_IP" "$TUNNEL_TYPE"
            ;;
        notunnel)
            TUNNEL_TYPE="gre"
            if [[ $# -gt 0 ]]; then
                TUNNEL_TYPE="$1"
            fi
            destroy_tunnel "$TUNNEL_TYPE"
            ;;
        mitm)
            if [[ $# -lt 1 ]]; then
                log_error "Specify enable or disable"
                exit 1
            fi
            if [[ "$1" == "enable" ]]; then
                ENABLE_MITM=1
            else
                ENABLE_MITM=0
            fi
            setup_mitm_capabilities
            ;;
        stealth)
            if [[ $# -lt 1 ]]; then
                log_error "Specify enable or disable"
                exit 1
            fi
            if [[ "$1" == "enable" ]]; then
                ENABLE_STEALTH=1
            else
                ENABLE_STEALTH=0
            fi
            configure_stealth_mode
            ;;
        exploit)
            if [[ $# -lt 3 ]]; then
                log_error "Target, service and port required for exploitation"
                exit 1
            fi
            TARGET="$1"
            SERVICE="$2"
            PORT="$3"
            TECHNIQUE="default"
            if [[ $# -gt 3 ]]; then
                TECHNIQUE="$4"
            fi
            exploit_vulnerable_service "$TARGET" "$SERVICE" "$PORT" "$TECHNIQUE"
            ;;
        traffic)
            INTERFACE=""
            DL_LIMIT="10mbit"
            UL_LIMIT="5mbit"
            if [[ $# -gt 0 ]]; then
                INTERFACE="$1"
            fi
            if [[ $# -gt 1 ]]; then
                DL_LIMIT="$2"
            fi
            if [[ $# -gt 2 ]]; then
                UL_LIMIT="$3"
            fi
            setup_traffic_shaping "$INTERFACE" "$DL_LIMIT" "$UL_LIMIT"
            ;;
        help)
            print_usage
            exit 0
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            print_usage
            exit 1
            ;;
    esac
}

init_framework() {
    log_info "Initializing NetOps Framework v$VERSION"
    
    init_directories
    
    setup_logging
    
    detect_interfaces
    
    if ! validate_environment; then
        log_error "Environment validation failed"
        return 1
    fi
    
    configure_ttl_manipulation
    
    log_info "NetOps Framework initialized successfully"
    
    return 0
}

if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
fi

parse_arguments "$@"
