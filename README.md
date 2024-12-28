# Enhanced P2P SSH Tunnel with NAT Traversal

## Description
This tool provides a robust and secure method for establishing peer-to-peer SSH tunnels through various NAT traversal methods including UPnP, STUN, and TURN. It features:

- **NAT Traversal:** Automatically detects and uses the best available method for establishing connections.
- **Dynamic DNS:** Supports DDNS updates to maintain connectivity with dynamic IP addresses.
- **Security:** Implements advanced key management, encryption, and connection validation.
- **Connection Monitoring:** Tracks and logs connection statistics with auto-recovery features.
- **Comprehensive Logging:** Detailed logs for debugging and monitoring.

## Installation

### Python and Dependencies
```bash
python3 -m pip install -r requirements.txt
```
Ensure you have Python 3.7+ installed. Dependencies include:
- `cryptography`
- `aiohttp`
- `aiodns`
- `miniupnpc`
- `requests`
- `pystun`

### Installation
Clone or download this repository to your local machine.

## Usage

### Setup the Tunnel
```bash
python3 p2p_tunnel.py setup --key-type ed25519
```
Generates SSH keys and configures the firewall.

### Connect to a Remote Host
```bash
python3 p2p_tunnel.py connect example.com
```
Establishes a tunnel to `example.com`. Use `--reverse` for reverse tunnels.

### Key Management
```bash
python3 p2p_tunnel.py keys --add "ssh-rsa AAAA... comment"
python3 p2p_tunnel.py keys --remove fingerprint
python3 p2p_tunnel.py keys --list
```
Add, remove, or list SSH keys.

### Dynamic DNS Management
```bash
python3 p2p_tunnel.py ddns --provider noip --hostname myhost.ddns.net --username user --password pass
```
Updates your DDNS record.

## Configuration
The tool uses `~/.ssh/p2p_tunnel.json` for configuration. Modify this file for custom settings.

## Security Considerations

- Keys are rotated every 90 days by default. Adjust this in the `KeyManager` class.
- Ensure only trusted keys are added to the authorized keys file.
- Use strong passwords for DDNS services and consider using environment variables or secure storage for sensitive information.

## Contributing
Pull requests, issues, and suggestions are welcome. Please see [CONTRIBUTING.md](link to CONTRIBUTING.md if available).
