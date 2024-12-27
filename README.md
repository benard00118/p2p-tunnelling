# p2p-tunnelling

# Enhanced P2P SSH Tunnel

A secure peer-to-peer SSH tunneling solution with modern security features and cross-platform support.

## Features

- Modern key types (Ed25519, RSA 4096-bit, ECDSA)
- Automatic firewall configuration
- Public/private IP detection
- Secure key management
- Cross-platform support (Linux, macOS, WSL)
- Logging and error tracking
- Multiple connection retry with backoff

## Installation

1. Create and activate virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate  # Windows
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Initial Setup

Generate SSH keys and configure your environment:
```bash
# Using modern Ed25519 keys (recommended)
python p2p_tunnel.py --setup --key-type ed25519

# With automatic firewall configuration
python p2p_tunnel.py --setup --configure-firewall
```

### Key Management

Add a friend's public key:
```bash
python p2p_tunnel.py --add-key "ssh-ed25519 AAAA..."
```

Remove a key:
```bash
python p2p_tunnel.py --remove-key "ssh-ed25519 AAAA..."
```

### Establish Connection

Connect to a remote host:
```bash
# Default port (22)
python p2p_tunnel.py --connect friend@192.168.1.100

# Custom port
python p2p_tunnel.py --connect friend@192.168.1.100 --port 2222
```

## Security Notes

1. Use Ed25519 keys when possible (faster and more secure than RSA)
2. Keep private keys secure (chmod 600)
3. Regularly rotate keys
4. Monitor logs for unauthorized access attempts

## Troubleshooting

1. Connection Issues:
   - Check if the port is open in the firewall
   - Verify both public and private IP connectivity
   - Check the logs in `tunnel.log`

2. Key Problems:
   - Ensure correct permissions on ~/.ssh directory (700)
   - Verify public key format
   - Check authorized_keys file permissions (600)

3. Firewall Issues:
   - Run with --configure-firewall
   - Manually verify firewall rules
   - Check system logs for blocked connections

## Logs

Logs are stored in `tunnel.log` in the current directory. They include:
- Connection attempts
- Key operations
- Error messages
- Security events

## Best Practices

1. Key Management:
   - Generate new keys periodically
   - Use passphrase protection for private keys
   - Keep backups of your keys
   - Never share private keys

2. Network Security:
   - Use non-standard ports when possible
   - Enable firewall logging
   - Monitor connection attempts
   - Use VPN when on public networks

3. System Security:
   - Keep system and dependencies updated
   - Use strong passwords for system accounts
   - Enable system auditing
   - Regular security updates
