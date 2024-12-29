

```markdown
# P2P SSH Tunnel with NAT Traversal

A robust and secure implementation of peer-to-peer SSH tunneling with advanced features:
- NAT traversal (UPnP, STUN, TURN)
- Dynamic DNS support
- Advanced security features
- Connection monitoring and auto-recovery
- Comprehensive logging

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Setup](#setup)
  - [Connect](#connect)
  - [Key Management](#key-management)
  - [Dynamic DNS (DDNS) Management](#dynamic-dns-ddns-management)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites
- Python 3.8 or higher
- Virtualenv (optional but recommended)
- Required Python packages (listed in `requirements.txt`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/benard00118/p2p-tunnelling.git
   cd p2p-ssh-tunnel
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration
The default configuration file is located at `~/.ssh/p2p_tunnel.json`. You can customize the configuration by editing this file.

Example configuration:
```json
{
  "ssh_port": 22,
  "key_type": "ed25519",
  "key_path": "~/.ssh/id_ed25519",
  "authorized_keys": "~/.ssh/authorized_keys",
  "known_hosts": "~/.ssh/known_hosts",
  "log_level": "INFO",
  "retry_attempts": 3,
  "retry_delay": 5,
  "trusted_keys": {},
  "security": {
    "min_key_size": 2048,
    "allowed_key_types": ["ed25519", "rsa"],
    "allowed_ciphers": [
      "chacha20-poly1305@openssh.com",
      "aes256-gcm@openssh.com"
    ],
    "allowed_macs": [
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com"
    ]
  }
}
```

## Usage

### Setup
To initialize and configure the tunnel:
```bash
python p2p_tunnelling/p2p_tunnel.py setup --key-type {ed25519,rsa,ecdsa} --force
```
Example:
```bash
python p2p_tunnelling/p2p_tunnel.py setup --key-type rsa --force
```

### Connect
To connect to a remote host using the tunnel:
```bash
python p2p_tunnelling/p2p_tunnel.py connect {remote_host} --port {PORT} --reverse --timeout {TIMEOUT}
```
Example:
```bash
python p2p_tunnelling/p2p_tunnel.py connect example.com --port 2222 --reverse --timeout 60
```

### Key Management
To manage SSH keys:
- Add a public key:
  ```bash
  python p2p_tunnelling/p2p_tunnel.py keys --add "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3..."
  ```
- Remove a key by fingerprint:
  ```bash
  python p2p_tunnelling/p2p_tunnel.py keys --remove {FINGERPRINT}
  ```
- List all keys:
  ```bash
  python p2p_tunnelling/p2p_tunnel.py keys --list
  ```

### Dynamic DNS (DDNS) Management
To manage DDNS settings:
```bash
python p2p_tunnelling/p2p_tunnel.py ddns --provider {PROVIDER} --hostname {HOSTNAME} --username {USERNAME} --password {PASSWORD}
```
Example:
```bash
python p2p_tunnelling/p2p_tunnel.py ddns --provider no-ip --hostname example.ddns.net --username myuser --password mypass
```

## Troubleshooting
- Ensure all dependencies are installed.
- Check the configuration file for errors.
- Use the `--log-level DEBUG` option for detailed logging.
- Ensure the firewall allows the necessary ports.

## Contributing
Contributions are welcome! Please submit a pull request or open an issue to discuss your ideas.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
