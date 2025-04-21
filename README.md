# netOps Framework

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

netOps Framework is a comprehensive toolkit designed for network operations, security analysis, and network topology manipulation. It provides a modular architecture for network professionals to perform sophisticated network auditing, traffic manipulation, and security assessment.

## ⚠️ Security Disclaimer

> This framework is designed for authorized network penetration testing, legitimate security research, and network administration. Usage must comply with all applicable laws and regulations. Unauthorized network manipulation may violate computer crime laws. Users assume all responsibility for proper, legal deployment.

## Core

The framework uses a modular architecture comprised of six specialized subsystems:

```
netOps Framework
├── Core Functions Module
├── Scanning Module
├── Exploitation Module
├── Auditing Module
├── Logging Module
└── Connection Module
```

## Key Capabilities

- **TTL Management**: Sophisticated TTL manipulation for traffic engineering
- **Network Topology Analysis**: Multi-tier network scanning and mapping
- **Security Auditing**: Comprehensive configuration assessment and vulnerability detection
- **Traffic Engineering**: Advanced packet manipulation and traffic shaping
- **Tunneling**: Multi-protocol tunnel establishment and management
- **Exploitation**: Service-specific vulnerability assessment and validation
- **Stealth Operations**: Low-observable network operations mode
- **MITM Capabilities**: Traffic interception and analysis functionality
- **Covert Channels**: Covert communication channel implementation

## System Requirements

- Linux operating system (tested on Debian/Ubuntu/RHEL)
- Root privileges
- Core dependencies:
  - nftables
  - ip (iproute2)
  - tcpdump
  - awk, grep, sed
- Kernel modules:
  - nf_tables
  - nf_nat
  - nf_conntrack
  - ip_gre (for tunneling)
  - ipip (for tunneling)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/CPScript/netOps
   cd netOps-framework
   ```

2. Make the script executable:
   ```bash
   chmod +x netOps.sh
   ```

3. Initialize the framework (creates necessary directories and configurations):
   ```bash
   sudo ./netOps.sh init
   ```

## Configuration

The framework uses the following directories by default:
- `/etc/netOps` - Configuration files
- `/var/log/netOps` - Log files
- `/etc/nftables.d` - NFTables rule definitions
- `/var/netOps/pcap` - Packet capture storage

Configuration parameters can be customized in the script or via a configuration file.

## Usage

### Basic Commands

```bash
# Initialize the framework
sudo ./netOps.sh init

# Configure TTL manipulation
sudo ./netOps.sh ttl 128

# Map subnet to specific TTL
sudo ./netOps.sh map-ttl 192.168.1.0/24:32

# Scan network (passive/active/deep)
sudo ./netOps.sh scan 192.168.0.0/24 active

# Audit network configuration (levels 1-3)
sudo ./netOps.sh audit 3

# Enable packet logging
sudo ./netOps.sh log eth0 "tcp port 80 or tcp port 443"

# Disable packet logging
sudo ./netOps.sh nolog

# Set up tunnel
sudo ./netOps.sh tunnel 192.168.100.1 wireguard

# Destroy tunnel
sudo ./netOps.sh notunnel wireguard

# Enable MITM capabilities
sudo ./netOps.sh mitm enable

# Enable stealth mode
sudo ./netOps.sh stealth enable

# Traffic shaping
sudo ./netOps.sh traffic eth0 20mbit 10mbit
```

### Command Options

```
Options:
  -v, --verbose             Enable verbose output
  -h, --help                Display help
  -c, --config <file>       Use specific configuration file
  -i, --interface <iface>   Specify network interface
```

## Implementation Details

The framework leverages several Linux networking subsystems:

1. **NFTables**: For packet filtering, manipulation, and NAT
2. **IP Commands**: For interface and routing configuration
3. **TCPDump**: For packet capture and analysis
4. **TC**: For traffic control and QoS

## Security Considerations

- **Privilege Requirements**: This framework requires root privileges
- **Network Disruption**: Improper configuration may disrupt network services
- **Exploitation**: Only use exploitation capabilities in authorized testing

## Advanced Usage Examples

### Network Scanning and Enumeration

```bash
# Passive network enumeration
sudo ./netOps.sh scan auto passive

# Deep scan with service detection
sudo ./netOps.sh scan 192.168.1.0/24 deep

# Network bottleneck detection
sudo ./netOps.sh detect_network_bottlenecks eth0 300
```

### Traffic Manipulation

```bash
# Set up transparent MITM proxy
sudo ./netOps.sh mitm enable
sudo ./netOps.sh setup_mitm_capabilities

# Configure custom TTL mapping
sudo ./netOps.sh map-ttl 10.0.0.0/8:128
sudo ./netOps.sh map-ttl 192.168.0.0/16:64
```

### Secure Tunneling

```bash
# Create WireGuard tunnel
sudo ./netOps.sh tunnel 10.10.10.1 wireguard

# Create GRE tunnel with specific parameters
sudo ./netOps.sh tunnel 192.168.100.1 gre
```

## Troubleshooting

Common issues and their solutions:

1. **NFTables Rules Not Applied**
   - Ensure nf_tables kernel module is loaded
   - Check for syntax errors in rules

2. **Interface Detection Failures**
   - Manually specify interface with -i flag
   - Verify interface is operational

3. **Permission Denied Errors**
   - Framework must be run with root privileges
   - Check directory permissions
## Disclaimer

This software is provided for educational and professional use only. Users are responsible for ensuring all usage complies with applicable laws and regulations. The authors accept no liability for misuse of this software.
