#!/usr/bin/env python3
import os
import sys
import argparse
import subprocess
import socket
import logging
import json
import platform
import requests
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Union
import re
import stat
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import shutil
import threading
import queue
import time

class KeyType(Enum):
    ED25519 = "ed25519"
    RSA = "rsa"
    ECDSA = "ecdsa"

@dataclass
class SystemInfo:
    platform: str
    is_wsl: bool
    firewall_type: Optional[str]

class TunnelError(Exception):
    """Custom exception for tunnel operations"""
    pass

@dataclass
class SSHKey:
    """SSH key configuration and metadata"""
    key_type: str
    public_key: str
    fingerprint: str
    added_date: str
    last_used: Optional[str] = None
    comment: Optional[str] = None

class TunnelConfig:
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path.home() / '.ssh' / 'p2p_tunnel.json'
        self.config: Dict = self._load_config()

    def _load_config(self) -> Dict:
        if self.config_path.exists():
            with open(self.config_path) as f:
                return json.load(f)
        return self._create_default_config()

    def _create_default_config(self) -> Dict:
        config = {
            'ssh_port': 22,
            'key_type': 'ed25519',
            'key_path': str(Path.home() / '.ssh' / 'id_ed25519'),
            'authorized_keys': str(Path.home() / '.ssh' / 'authorized_keys'),
            'known_hosts': str(Path.home() / '.ssh' / 'known_hosts'),
            'log_level': 'INFO',
            'retry_attempts': 3,
            'retry_delay': 5,
            'trusted_keys': {}
        }
        self._save_config(config)
        return config

    def _save_config(self, config: Dict) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

class KeyManager:
    def __init__(self, config: TunnelConfig):
        self.config = config
        self.logger = logging.getLogger('KeyManager')

    def generate_key(self, key_type: str = None) -> Path:
        key_type = key_type or self.config.config['key_type']
        key_path = Path(self.config.config['key_path'])

        if key_type not in ['ed25519', 'rsa', 'ecdsa']:
            raise ValueError(f"Unsupported key type: {key_type}")

        cmd = [
            'ssh-keygen',
            '-t', key_type,
            '-f', str(key_path),
            '-N', ''  # Empty passphrase
        ]
        
        if key_type == 'ed25519':
            cmd.extend(['-a', '100'])  # Increase KDF rounds for ed25519
        elif key_type == 'rsa':
            cmd.extend(['-b', '4096'])  # 4096 bits for RSA

        subprocess.run(cmd, check=True)

        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
        key_path.with_suffix('.pub').chmod(
            stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH  # 644
        )

        return key_path

    def validate_public_key(self, key_str: str) -> bool:
        valid_types = ['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256']
        key_parts = key_str.strip().split()
        
        if len(key_parts) < 2:
            return False
            
        key_type = key_parts[0]
        return key_type in valid_types

    def add_public_key(self, key_str: str, comment: Optional[str] = None) -> None:
        if not self.validate_public_key(key_str):
            raise ValueError("Invalid public key format")

        key_data = SSHKey(
            key_type=key_str.split()[0],
            public_key=key_str,
            fingerprint=self._get_key_fingerprint(key_str),
            added_date=datetime.now().isoformat(),
            comment=comment
        )

        self.config.config['trusted_keys'][key_data.fingerprint] = vars(key_data)
        self.config._save_config(self.config.config)

        auth_keys_path = Path(self.config.config['authorized_keys'])
        auth_keys_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(auth_keys_path, 'a+') as f:
            f.write(f'{key_str}\n')

        auth_keys_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600

    def remove_public_key(self, fingerprint: str) -> bool:
        if fingerprint not in self.config.config['trusted_keys']:
            return False

        key_data = self.config.config['trusted_keys'][fingerprint]
        auth_keys_path = Path(self.config.config['authorized_keys'])

        if auth_keys_path.exists():
            with open(auth_keys_path) as f:
                keys = f.readlines()

            with open(auth_keys_path, 'w') as f:
                for key in keys:
                    if self._get_key_fingerprint(key) != fingerprint:
                        f.write(key)

        del self.config.config['trusted_keys'][fingerprint]
        self.config._save_config(self.config.config)
        return True

    def _get_key_fingerprint(self, key_str: str) -> str:
        proc = subprocess.run(
            ['ssh-keygen', '-lf', '/dev/stdin'],
            input=key_str.encode(),
            capture_output=True,
            text=True
        )
        if proc.returncode != 0:
            raise RuntimeError(f"Error computing fingerprint: {proc.stderr}")
        return proc.stdout.split()[1]

    def share_public_key(self, email_address: str):
        # Placeholder for sending public key via email securely
        public_key_content = Path(self.config.config['key_path'] + '.pub').read_text()
        self.logger.info(f"Would send public key to {email_address}")
        # Implement actual secure email sending here

class SecurityManager:
    VALID_KEY_PATTERNS = {
        'ssh-rsa': re.compile(r'^ssh-rsa AAAA[0-9A-Za-z+/]+[=]{0,3}.*$'),
        'ssh-ed25519': re.compile(r'^ssh-ed25519 AAAA[0-9A-Za-z+/]+[=]{0,3}.*$'),
        'ecdsa-sha2-nistp256': re.compile(r'^ecdsa-sha2-nistp256 AAAA[0-9A-Za-z+/]+[=]{0,3}.*$')
    }

    def __init__(self, ssh_dir: Path):
        self.ssh_dir = ssh_dir
        self.ssh_dir.mkdir(mode=0o700, exist_ok=True)
        
    def generate_key(self, key_type: KeyType = KeyType.ED25519) -> Path:
        key_path = self.ssh_dir / f"id_{key_type.value}"
        
        if key_path.exists():
            raise TunnelError(f"Key {key_path} already exists. Use --force to overwrite.")
        
        cmd = [
            'ssh-keygen',
            '-t', key_type.value,
            '-f', str(key_path),
            '-N', ''  # Empty passphrase
        ]
        
        if key_type == KeyType.RSA:
            cmd.extend(['-b', '4096'])  # Use 4096 bits for RSA
            
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            key_path.chmod(0o600)
            key_path.with_suffix('.pub').chmod(0o644)
            return key_path
        except subprocess.CalledProcessError as e:
            raise TunnelError(f"Failed to generate key: {e.stderr.decode()}")

    def validate_public_key(self, key_content: str) -> bool:
        key_content = key_content.strip()
        return any(pattern.match(key_content) for pattern in self.VALID_KEY_PATTERNS.values())

    def add_authorized_key(self, public_key: str) -> None:
        if not self.validate_public_key(public_key):
            raise TunnelError("Invalid public key format")
            
        auth_keys_path = self.ssh_dir / 'authorized_keys'
        
        try:
            with open(auth_keys_path, 'a+') as f:
                f.seek(0)
                if public_key not in f.read():
                    f.write(f'\n{public_key}\n')
            auth_keys_path.chmod(0o600)
        except Exception as e:
            raise TunnelError(f"Failed to add authorized key: {e}")

    def remove_authorized_key(self, public_key: str) -> None:
        auth_keys_path = self.ssh_dir / 'authorized_keys'
        
        try:
            if auth_keys_path.exists():
                with open(auth_keys_path, 'r') as f:
                    keys = f.readlines()
                
                with open(auth_keys_path, 'w') as f:
                    for key in keys:
                        if key.strip() != public_key.strip():
                            f.write(key)
        except Exception as e:
            raise TunnelError(f"Failed to remove authorized key: {e}")

class NetworkManager:
    def __init__(self, system_info: SystemInfo):
        self.system_info = system_info

    def get_public_ip(self) -> Optional[str]:
        try:
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            return response.json()['ip']
        except Exception:
            return None

    def configure_firewall(self, port: int) -> None:
        if self.system_info.platform == "Linux":
            if shutil.which('ufw'):
                cmd = ['sudo', 'ufw', 'allow', str(port)]
            elif shutil.which('firewalld'):
                cmd = ['sudo', 'firewall-cmd', '--add-port', f'{port}/tcp', '--permanent']
            else:
                return
                
            try:
                subprocess.run(cmd, check=True)
                if shutil.which('firewalld'):
                    subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=True)
            except subprocess.CalledProcessError as e:
                raise TunnelError(f"Failed to configure firewall: {e}")

class FirewallManager:
    def __init__(self):
        self.platform = platform.system().lower()
        self.logger = logging.getLogger('FirewallManager')

    def configure_firewall(self, port: int) -> bool:
        try:
            if self.platform == 'linux':
                return self._configure_linux_firewall(port)
            elif self.platform == 'darwin':
                return self._configure_macos_firewall(port)
            elif self.platform == 'windows':
                return self._configure_windows_firewall(port)
            else:
                self.logger.warning(f"Unsupported platform: {self.platform}")
                return False
        except Exception as e:
            self.logger.error(f"Firewall configuration failed: {e}")
            return False

    def _configure_linux_firewall(self, port: int) -> bool:
        if shutil.which('ufw'):
            cmd = ['sudo', 'ufw', 'allow', str(port)]
        elif shutil.which('iptables'):
            cmd = [
                'sudo', 'iptables', '-A', 'INPUT',
                '-p', 'tcp', '--dport', str(port),
                '-j', 'ACCEPT'
            ]
        else:
            self.logger.warning("No supported firewall found on Linux")
            return False

        subprocess.run(cmd, check=True)
        return True

    def _configure_macos_firewall(self, port: int) -> bool:
        cmd = ['sudo', 'pfctl', '-d', '-f', '/etc/pf.conf']  # Disable pf
        cmd2 = ['echo', f'pass in proto tcp from any to any port {port}', '|', 'sudo', 'pfctl', '-Ef', '-']
        try:
            subprocess.run(cmd, check=True)
            subprocess.run(cmd2, check=True, shell=True)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to configure macOS firewall: {e}")
            return False

    def _configure_windows_firewall(self, port: int) -> bool:
        cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=SSH', 'dir=in', 
               'action=allow', 'protocol=TCP', 'localport={}'.format(port)]
        try:
            subprocess.run(cmd, check=True)
            return True
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to configure Windows firewall: {e}")
            return False

class DynamicDNS:
    def __init__(self, service_url: str, username: str, password: str, hostname: str):
        self.service_url = service_url
        self.auth = (username, password)
        self.hostname = hostname

    def update_ip(self):
        try:
            response = requests.get(self.service_url, auth=self.auth, params={'hostname': self.hostname})
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise TunnelError(f"Failed to update DDNS: {e}")

class TunnelManager:
    def __init__(self, security: SecurityManager, network: NetworkManager):
        self.security = security
        self.network = network
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        logger = logging.getLogger('p2p_tunnel')
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        log_file = Path('tunnel.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger

    def start_tunnel(self, remote_host: str, port: int = 22, retry_count: int = 3) -> None:
        self.logger.info(f"Starting tunnel to {remote_host}:{port}")
        
        for attempt in range(retry_count):
            try:
                cmd = [
                    'sshuttle',
                    '--dns',
                    '--remote', f'ssh://{remote_host}:{port}',
                    '0/0'
                ]
                
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                while True:
                    return_code = process.poll()
                    if return_code is not None:
                        raise TunnelError(f"Tunnel process exited with code {return_code}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                self.logger.info("Tunnel closed by user")
                break
            except Exception as e:
                self.logger.error(f"Attempt {attempt + 1} failed: {e}")
                if attempt < retry_count - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise TunnelError("Failed to establish tunnel after retries")

    def start_reverse_tunnel(self, remote_host: str, remote_port: int, local_port: int):
        """Start a reverse SSH tunnel to connect from server to client"""
        cmd = [
            'ssh', '-fNT',
            '-R', f'{remote_port}:localhost:{local_port}',
            f'{remote_host}'
        ]
        
        try:
            subprocess.run(cmd, check=True)
            self.logger.info(f"Reverse tunnel established from {remote_host} to localhost:{local_port}")
        except subprocess.CalledProcessError as e:
            raise TunnelError(f"Failed to establish reverse tunnel: {e}")

    def test_connection(self, remote_host: str, remote_port: int):
        """Test if the tunnel is working"""
        try:
            socket.create_connection((remote_host, remote_port), timeout=5)
            self.logger.info(f"Connection test passed for {remote_host}:{remote_port}")
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Enhanced P2P SSH Tunnel')
    
    parser.add_argument('--setup', action='store_true', help='Initial setup')
    parser.add_argument('--key-type', choices=['ed25519', 'rsa', 'ecdsa'], 
                       default='ed25519', help='SSH key type')
    parser.add_argument('--force', action='store_true', help='Force overwrite existing keys')
    parser.add_argument('--add-key', help='Add friend\'s public key')
    parser.add_argument('--remove-key', help='Remove friend\'s public key')
    parser.add_argument('--connect', help='Connect to remote host')
    parser.add_argument('--port', type=int, default=22, help='Remote SSH port')
    parser.add_argument('--configure-firewall', action='store_true', 
                       help='Configure firewall for SSH')
    parser.add_argument('--reverse-tunnel', action='store_true', help='Set up a reverse SSH tunnel')
    parser.add_argument('--test-connection', action='store_true', help='Test the tunnel connection')
    parser.add_argument('--ddns', nargs=3, metavar=('service_url', 'username', 'password'), help='Update DDNS')
    parser.add_argument('--share-key', help='Share public key with an email address')

    args = parser.parse_args()
    
    try:
        system_info = SystemInfo(
            platform=platform.system(),
            is_wsl='Microsoft' in platform.uname().release,
            firewall_type=None  # Detected during runtime
        )
        
        security = SecurityManager(Path.home() / '.ssh')
        network = NetworkManager(system_info)
        tunnel = TunnelManager(security, network)
        key_manager = KeyManager(TunnelConfig())
        
        if args.setup:
            key_path = security.generate_key(KeyType[args.key_type.upper()])
            print(f"\nGenerated {args.key_type} key pair at {key_path}")
            
            local_ip = socket.gethostbyname(socket.gethostname())
            public_ip = network.get_public_ip()
            print(f"\nLocal IP: {local_ip}")
            if public_ip:
                print(f"Public IP: {public_ip}")
            
            if args.configure_firewall:
                network.configure_firewall(args.port)
                print(f"\nFirewall configured for port {args.port}")
                
        elif args.add_key:
            security.add_authorized_key(args.add_key)
            print("Public key added successfully")
            
        elif args.remove_key:
            security.remove_authorized_key(args.remove_key)
            print("Public key removed successfully")
            
        elif args.connect:
            tunnel.start_tunnel(args.connect, args.port)
            
        elif args.reverse_tunnel:
            # Here you would need to know the remote port and local port you want to forward
            tunnel.start_reverse_tunnel(args.connect, args.port, 22)  # Example, adjust as needed
            
        elif args.test_connection:
            if tunnel.test_connection(args.connect, args.port):
                print("Tunnel connection successful")
            else:
                print("Failed to connect through the tunnel")
        
        elif args.ddns:
            ddns = DynamicDNS(args.ddns[0], args.ddns[1], args.ddns[2], "yourhostname.ddns.net")
            response = ddns.update_ip()
            print(f"DDNS updated: {response}")

        elif args.share_key:
            key_manager.share_public_key(args.share_key)

    except TunnelError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)

if __name__ == '__main__':
    main()
