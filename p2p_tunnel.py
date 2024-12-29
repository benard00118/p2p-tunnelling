#!/usr/bin/env python3
"""
Enhanced P2P SSH Tunnel with NAT Traversal
A robust and secure implementation of peer-to-peer SSH tunneling with advanced features:
- NAT traversal (UPnP, STUN, TURN)
- Dynamic DNS support
- Advanced security features
- Connection monitoring and auto-recovery
- Comprehensive logging
"""
import stun
import base64
import hashlib
import os
import ssl
import sys
import argparse
import asyncio
import json
import logging
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Any
import stat
import re
import shutil


import aiohttp
import aiodns
import miniupnpc
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption



# Constants
DEFAULT_CONFIG_PATH = Path.home() / '.ssh' / 'p2p_tunnel.json'
DEFAULT_LOG_PATH = Path.home() / '.ssh' / 'p2p_tunnel.log'
STUN_SERVERS = [
    'stun.l.google.com:19302',
    'stun1.l.google.com:19302',
    'stun2.l.google.com:19302'
]

class TunnelType(Enum):
    """Tunnel connection types"""
    DIRECT = auto()
    UPNP = auto()
    STUN = auto()
    RELAY = auto()

class KeyType(Enum):
    """SSH key types"""
    ED25519 = "ed25519"
    RSA = "rsa"
    ECDSA = "ecdsa"

@dataclass
class SystemInfo:
    """System information"""
    platform: str
    is_wsl: bool
    firewall_type: Optional[str]
    arch: str
    python_version: str

@dataclass
class ConnectionInfo:
    """Connection information"""
    local_ip: str
    public_ip: str
    nat_type: Optional[str]
    mapped_port: int
    tunnel_type: TunnelType
    stun_server: Optional[str] = None
    relay_server: Optional[str] = None

@dataclass
class SSHKey:
    """SSH key metadata"""
    key_type: str
    public_key: str
    fingerprint: str
    added_date: str
    last_used: Optional[str] = None
    comment: Optional[str] = None

class TunnelError(Exception):
    """Custom exception for tunnel operations"""
    pass



class TunnelConfig:
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path.home() / '.ssh' / 'p2p_tunnel.json'
        self.config: Dict = self._load_config()

        # Ensure sensitive data is not hardcoded
        self.config['password'] = os.getenv('P2P_TUNNEL_PASSWORD', self.config.get('password'))
        self.config['api_key'] = os.getenv('P2P_TUNNEL_API_KEY', self.config.get('api_key'))

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
        os.chmod(self.config_path, 0o600)  # Ensure the config file has secure permissions

class KeyManager:
    def __init__(self, config: TunnelConfig):
        self.config = config
        self.logger = logging.getLogger('KeyManager')

    def generate_key(self, key_type: str = None) -> Path:
        key_type = key_type or self.config.config['key_type']
        key_path = Path(self.config.config['key_path'])

        if key_type == 'ed25519':
            private_key = ed25519.Ed25519PrivateKey.generate()
        elif key_type == 'rsa':
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096  # 4096 bits for RSA
            )
        else:
            raise ValueError(f"Unsupported key type: {key_type}")

        # Save private key
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        with open(key_path, 'wb') as f:
            f.write(private_pem)

        # Save public key
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        public_key_path = key_path.with_suffix('.pub')
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        # Set permissions
        key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 600
        public_key_path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 644

        return key_path
    def rotate_keys(self, rotation_period_days: int = 90):
        # Check if the current key is older than the rotation period
        current_key_path = Path(self.config.config['key_path'])
        if current_key_path.exists():
            key_creation_time = datetime.fromtimestamp(current_key_path.stat().st_ctime)
            if (datetime.now() - key_creation_time).days >= rotation_period_days:
                self.logger.info("Rotating SSH keys due to expiration")
                self.generate_key()
                self._update_config_with_new_key()
    
    def _update_config_with_new_key(self):
        new_key_path = self.config.config['key_path'].replace('.old', '')  # Or whatever naming scheme you use
        self.config.config['key_path'] = new_key_path
        self.config._save_config(self.config.config)
        
    def validate_public_key(self, key_str: str) -> bool:
        parts = key_str.strip().split()
        if len(parts) != 3:  # Key type, key data, comment
            return False
        
        key_type, key_data, _ = parts
        valid_types = ['ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256']
        
        if key_type not in valid_types:
            return False
        
        # Validate base64 encoding for key data
        try:
            base64.b64decode(key_data)
        except:
            return False
        
        return True

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
            new_keys = []

            for key in keys:
                if self._get_key_fingerprint(key) != fingerprint:
                    new_keys.append(key)
            
            with open(auth_keys_path, 'w') as f:
                f.writelines(new_keys)

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

class ConfigManager:
    """Configuration management with validation"""
    
    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self.config: Dict[str, Any] = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load and validate configuration"""
        if not self.config_path.exists():
            return self._create_default_config()
            
        try:
            with open(self.config_path) as f:
                config = json.load(f)
            self._validate_config(config)
            return config
        except Exception as e:
            raise TunnelError(f"Failed to load configuration: {e}")
            
    def _create_default_config(self) -> Dict[str, Any]:
        """Create default configuration"""
        config = {
            'ssh_port': 22,
            'key_type': 'ed25519',
            'key_path': str(Path.home() / '.ssh' / 'id_ed25519'),
            'authorized_keys': str(Path.home() / '.ssh' / 'authorized_keys'),
            'known_hosts': str(Path.home() / '.ssh' / 'known_hosts'),
            'log_level': 'INFO',
            'retry_attempts': 3,
            'retry_delay': 5,
            'connection_timeout': 30,
            'keep_alive_interval': 60,
            'trusted_keys': {},
            'security': {
                'min_key_size': 2048,
                'allowed_key_types': ['ed25519', 'rsa'],
                'allowed_ciphers': [
                    'chacha20-poly1305@openssh.com',
                    'aes256-gcm@openssh.com'
                ],
                'allowed_macs': [
                    'hmac-sha2-512-etm@openssh.com',
                    'hmac-sha2-256-etm@openssh.com'
                ]
            }
        }
        self._save_config(config)
        return config
        
    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration structure and values"""
        required_fields = [
            'ssh_port', 'key_type', 'key_path', 'authorized_keys',
            'known_hosts', 'security'
        ]
        
        missing = [field for field in required_fields if field not in config]
        if missing:
            raise ValueError(f"Missing required config fields: {missing}")
            
        if not isinstance(config['ssh_port'], int) or not 1 <= config['ssh_port'] <= 65535:
            raise ValueError("Invalid SSH port number")
            
        if config['key_type'] not in ['ed25519', 'rsa', 'ecdsa']:
            raise ValueError("Invalid key type")
            
    def _save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)

class ConnectionMetrics:
    """Connection metrics tracking"""
    def __init__(self):
        self.total_connections = 0
        self.active_connections = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.connection_durations: List[float] = []

    async def record_connection_started(self):
        """Record new connection"""
        self.total_connections += 1
        self.active_connections += 1

    async def record_connection_closed(self):
        """Record connection closure"""
        self.active_connections -= 1

    async def record_traffic(self, bytes_sent: int, bytes_received: int):
        """Record traffic metrics"""
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received

class RateLimiter:
    """Rate limiting implementation"""
    def __init__(self, max_attempts: int = 3, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.attempts: Dict[str, List[float]] = {}
        self._cleanup_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start rate limiter with cleanup"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def stop(self):
        """Stop rate limiter"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

    async def check_rate_limit(self, key: str) -> bool:
        """Check if rate limit is exceeded"""
        now = time.time()
        if key not in self.attempts:
            self.attempts[key] = []

        # Clean old attempts
        self.attempts[key] = [t for t in self.attempts[key]
                            if now - t < self.window_seconds]

        if len(self.attempts[key]) >= self.max_attempts:
            return False

        self.attempts[key].append(now)
        return True

    async def _periodic_cleanup(self):
        """Periodically clean up old rate limit records"""
        while True:
            try:
                await asyncio.sleep(60)
                now = time.time()
                keys_to_remove = []

                for key, attempts in self.attempts.items():
                    # Remove attempts older than window
                    self.attempts[key] = [t for t in attempts
                                        if now - t < self.window_seconds]
                    # Remove empty keys
                    if not self.attempts[key]:
                        keys_to_remove.append(key)

                for key in keys_to_remove:
                    del self.attempts[key]

            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Rate limiter cleanup error: {e}")

class SecurityManager:
    """
    Enhanced security manager with improved key handling, validation, and protection
    """
    def __init__(self, config_path: Path, logger: logging.Logger):
        self.config_path = config_path
        self.logger = logger
        self.rate_limiter = RateLimiter()
        self.key_cache: Dict[str, Dict] = {}
        self.cert_fingerprints: Set[str] = set()
        self._load_trusted_fingerprints()

    def _load_trusted_fingerprints(self) -> None:
        """Load trusted certificate fingerprints"""
        try:
            cert_path = self.config_path / 'trusted_certs.json'
            if cert_path.exists():
                with open(cert_path) as f:
                    data = json.load(f)
                    self.cert_fingerprints = set(data.get('fingerprints', []))
        except Exception as e:
            self.logger.error(f"Failed to load trusted fingerprints: {e}")

    async def validate_connection(self, remote_host: str, port: int, ssl_context: Optional[ssl.SSLContext] = None) -> bool:
        try:
            async with asyncio.timeout(5):
                if ssl_context:
                    reader, writer = await asyncio.open_connection(remote_host, port, ssl=ssl_context)
                else:
                    reader, writer = await asyncio.open_connection(remote_host, port)

                try:
                    # Send version identification
                    writer.write(b"SSH-2.0-P2PTunnel_Enhanced\r\n")
                    await writer.drain()

                    # Read response with timeout
                    response = await reader.readline()
                    if not response.startswith(b"SSH-2.0"):
                        self.logger.warning(f"Invalid SSH response from {remote_host}")
                        return False

                    # Verify certificate if SSL is used
                    if ssl_context and writer.get_extra_info('ssl_object'):
                        cert = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
                        if not self._verify_certificate(cert):
                            return False

                    return True

                finally:
                    writer.close()
                    await writer.wait_closed()

        except asyncio.TimeoutError:
            self.logger.error(f"Connection timeout to {remote_host}")
            return False
        except ConnectionError as e:
            self.logger.error(f"Connection error to {remote_host}: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Validation error for {remote_host}: {e}")
            return False

    def _verify_certificate(self, cert_data: bytes) -> bool:
        """Verify SSL certificate against trusted fingerprints"""
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            return fingerprint in self.cert_fingerprints
        except Exception as e:
            self.logger.error(f"Certificate verification failed: {e}")
            return False

    async def add_authorized_key(self, key_data: str, comment: Optional[str] = None) -> bool:
        """
        Add authorized key with enhanced validation
        """
        try:
            # Validate key format
            if not self._validate_key_format(key_data):
                raise ValueError("Invalid key format")

            # Check key strength
            if not self._check_key_strength(key_data):
                raise ValueError("Key does not meet strength requirements")

            # Generate key fingerprint
            fingerprint = self._generate_key_fingerprint(key_data)

            # Add to authorized keys with proper permissions
            auth_keys_path = self.config_path / 'authorized_keys'
            auth_keys_path.parent.mkdir(parents=True, exist_ok=True)

            # Add with atomic write
            temp_path = auth_keys_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                f.write(f'{key_data} {comment or ""}\n')

            temp_path.chmod(0o600)
            temp_path.rename(auth_keys_path)

            # Update key cache
            self.key_cache[fingerprint] = {
                'key': key_data,
                'comment': comment,
                'added_at': datetime.now().isoformat(),
                'last_used': None
            }

            self.logger.info(f"Added authorized key: {fingerprint}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add authorized key: {e}")
            return False

    def _validate_key_format(self, key_data: str) -> bool:
        """Validate SSH key format"""
        try:
            parts = key_data.split()
            if len(parts) < 2:
                return False

            key_type = parts[0]
            key_data = parts[1]

            # Validate key type
            valid_types = {'ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256'}
            if key_type not in valid_types:
                return False

            # Validate key data format
            import base64
            try:
                base64.b64decode(key_data)
                return True
            except:
                return False

        except Exception:
            return False

    def _check_key_strength(self, key_data: str) -> bool:
        """Check if key meets minimum strength requirements"""
        try:
            parts = key_data.split()
            key_type = parts[0]
            key_material = parts[1]

            if key_type == 'ssh-rsa':
                # RSA key should be at least 3072 bits
                decoded = len(base64.b64decode(key_material)) * 8
                return decoded >= 3072
            elif key_type == 'ssh-ed25519':
                # Ed25519 keys are always 256 bits
                return True
            elif key_type == 'ecdsa-sha2-nistp256':
                # ECDSA keys should use nistp256 or stronger
                return True
            return False
        except Exception:
            return False
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
                    status_cmd = ['sudo', 'systemctl', 'is-active', 'firewalld']
                    status_result = subprocess.run(status_cmd, check=False, capture_output=True, text=True)
                    if 'active' in status_result.stdout.strip():
                        subprocess.run(['sudo', 'firewall-cmd', '--reload'], check=True)
                    else:
                        logging.warning("FirewallD is not running. Skipping reload.")
            except subprocess.CalledProcessError as e:
                raise TunnelError(f"Failed to configure firewall: {e}")

    async def test_connectivity(self, host: str, port: int, timeout: int) -> bool:
        """Test connectivity to the remote host and port within the given timeout."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionError) as e:
            logging.error(f"Connection test failed: {e}")
            return False

class CommandHandler:
    """Handles execution of different commands"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Initialize managers
        self.system_info = self._get_system_info()
        self.security_manager = SecurityManager(Path.home() / '.ssh', self.logger)
        self.network_manager = NetworkManager(self.system_info)
        self.key_manager = KeyManager(TunnelConfig(Path.home() / '.ssh' / 'p2p_tunnel.json'))  # Initialize KeyManager
        self.tunnel_manager = TunnelManager(config)
    
    async def handle_setup(self, args: argparse.Namespace) -> None:
        """Handle setup command"""
        try:
            # Generate SSH key
            key_path = self.key_manager.generate_key(
                key_type=args.key_type  # Removed await since generate_key is not async
            )
            self.logger.info(f"Generated {args.key_type} key pair at {key_path}")
            
            # Configure firewall
            port = self.config['ssh_port']
            self.network_manager.configure_firewall(port)
            self.logger.info(f"Configured firewall for port {port}")
            
            # Get network information
            net_info = self.network_manager.get_network_info()
            self.logger.info(f"Local IP: {net_info.local_ip}")
            if net_info.public_ip:
                self.logger.info(f"Public IP: {net_info.public_ip}")
                
        except Exception as e:
            self.logger.error(f"Setup failed: {e}")
            raise

    async def handle_connect(self, args: argparse.Namespace) -> None:
        """Handle connect command"""
        try:
            # Verify connectivity
            if not await self.network_manager.test_connectivity(
                args.remote_host,
                args.port,
                timeout=args.timeout
            ):
                raise TunnelError("Unable to reach remote host")
            
            # Start tunnel
            if args.reverse:
                await self.tunnel_manager.start_reverse_tunnel(
                    args.remote_host,
                    args.port
                )
            else:
                await self.tunnel_manager.start_tunnel(
                    args.remote_host,
                    args.port
                )
            
            self.logger.info(f"Connected to {args.remote_host}:{args.port}")
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise
        
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

class TunnelType(Enum):
    DIRECT = "direct"
    UPNP = "upnp"
    STUN = "stun"
    RELAY = "relay"

@dataclass
class ConnectionInfo:
    local_ip: str
    public_ip: str
    nat_type: str
    mapped_port: int
    tunnel_type: TunnelType
    stun_server: Optional[str] = None
    relay_server: Optional[str] = None

class NATTraversal:
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.upnp = None
        self.timeout = 30  # seconds
        self.max_retries = 3
        self.stun_servers = [
            'stun.l.google.com:19302',
            'stun1.l.google.com:19302',
            'stun2.l.google.com:19302',
            'stun.ekiga.net',  
            'stun.ideasip.com'
        ]
        self.relay_servers = [
            'relay1.example.com:3478',
            'relay2.example.com:3478'
        ]
        self.turn_servers = [
            'turn:turn.example.com:3478',
            'turn:turn2.example.com:3478'
        ]

    async def initialize(self):
        """Initialize NAT traversal components with retry logic"""
        for attempt in range(self.max_retries):
            try:
                self.upnp = miniupnpc.UPnP()
                self.upnp.discoverdelay = 200
                devices = await asyncio.wait_for(
                    self._discover_devices(),
                    timeout=self.timeout
                )
                if devices > 0:
                    self.upnp.selectigd()
                    await self._validate_upnp_connection()
                    return
            except asyncio.TimeoutError:
                self.logger.warning(f"UPnP discovery timeout (attempt {attempt + 1}/{self.max_retries})")
            except Exception as e:
                self.logger.warning(f"UPnP initialization failed (attempt {attempt + 1}/{self.max_retries}): {e}")
        self.upnp = None
    
    async def _discover_devices(self):
        """Async wrapper for UPnP device discovery"""
        return await asyncio.to_thread(self.upnp.discover)

    async def _validate_upnp_connection(self):
        """Validate UPnP connection and capabilities"""
        try:
            external_ip = await asyncio.to_thread(self.upnp.externalipaddress)
            wan_service = self.upnp.get_service_type()
            if not wan_service:
                raise ValueError("No WANIPConnection service found")
            self.logger.info(f"UPnP connection validated. External IP: {external_ip}")
        except Exception as e:
            raise RuntimeError(f"UPnP validation failed: {e}")

    async def get_connection_info(self, local_port: int) -> ConnectionInfo:
        """Determine the best connection method and return connection info"""
        local_ip = self._get_local_ip()
        public_ip = None
        nat_type = None
        mapped_port = local_port
        tunnel_type = TunnelType.DIRECT

        # Try UPnP first
        if self.upnp:
            try:
                public_ip = self.upnp.externalipaddress()
                self.upnp.addportmapping(
                    local_port, 'TCP', self.upnp.lanaddr, local_port,
                    'P2P Tunnel', ''
                )
                tunnel_type = TunnelType.UPNP
                self.logger.info(f"UPnP port mapping successful: {local_port} -> {mapped_port}")
            except Exception as e:
                self.logger.warning(f"UPnP port mapping failed: {e}")

        # If UPnP fails, try STUN
        if not public_ip:
            nat_info = await self._get_stun_info(local_port)
            if nat_info:
                public_ip, mapped_port = nat_info
                tunnel_type = TunnelType.STUN
                self.logger.info(f"STUN successful: {public_ip}:{mapped_port}")

        # If both fail, use relay
        if not public_ip:
            relay_info = await self._get_relay_info()
            if relay_info:
                public_ip, mapped_port = relay_info
                tunnel_type = TunnelType.RELAY
                self.logger.info(f"Using relay server: {public_ip}:{mapped_port}")

        return ConnectionInfo(
            local_ip=local_ip,
            public_ip=public_ip or local_ip,
            nat_type=nat_type,
            mapped_port=mapped_port,
            tunnel_type=tunnel_type
        )

    def _get_local_ip(self) -> str:
        """Get the local IP address"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
        finally:
            s.close()
    
   
    async def _get_stun_info(self, local_port: int) -> Optional[Tuple[str, int]]:
        """Get public IP and port using STUN"""
        for stun_server in self.stun_servers:
            try:
                # Assuming 'stun' has a method 'get_ip_info' like pystun
                nat_type, public_ip, public_port = stun.get_ip_info(
                    source_port=local_port,
                    stun_host=stun_server.split(':')[0],
                    stun_port=int(stun_server.split(':')[1])
                )
                if public_ip:
                    return public_ip, public_port
            except Exception as e:
                self.logger.warning(f"STUN request failed for {stun_server}: {e}")
        return None

    

    def cleanup(self):
        if self.upnp:
            try:
                self.logger.info("Cleaning up UPnP port mappings")
                for mapping in self.upnp.getportmappings():  # Assuming you keep track of mappings
                    self.upnp.deleteportmapping(mapping[0], 'TCP')
            except Exception as e:
                self.logger.error(f"Error cleaning up UPnP mappings: {e}")


class EnhancedDDNS:
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.cache_file = Path('.ddns_cache')
        self.update_interval = 300  # 5 minutes
        self.resolver = aiodns.DNSResolver()

    async def update(self) -> bool:
        """Update DDNS if necessary"""
        current_ip = await self._get_public_ip()
        cached_ip = await self._get_cached_ip()

        if current_ip == cached_ip:
            self.logger.debug("IP hasn't changed, skipping update")
            return True

        if await self._update_ddns_record(current_ip):
            await self._cache_ip(current_ip)
            if await self._verify_dns_propagation():
                self.logger.info(f"DDNS updated successfully to {current_ip}")
                return True
            else:
                self.logger.error("DNS propagation verification failed")
                return False
        return False

    async def _make_ddns_request(self, ip: str) -> aiohttp.ClientResponse:
        """Make the DDNS update request to the provider"""
        provider = self.config['provider']
        hostname = self.config['hostname']
        username = self.config['username']
        password = self.config['password']

        if provider == 'no-ip':
            url = f"https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ip}"
            auth = aiohttp.BasicAuth(username, password)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth) as response:
                    response_text = await response.text()
                    self.logger.debug(f"DDNS response: {response_text}")
                    if "good" in response_text or "nochg" in response_text:
                        return response
                    else:
                        self.logger.error(f"DDNS update failed: {response_text}")
                        raise Exception(f"DDNS update failed: {response_text}")
        else:
            raise NotImplementedError(f"DDNS provider '{provider}' is not supported")
            
    async def _get_public_ip(self) -> Optional[str]:
        """Get public IP using multiple services"""
        ip_services = [
            'https://api.ipify.org?format=json',
            'https://ifconfig.me/ip',
            'https://api.ip.sb/ip'
        ]
        
        for service in ip_services:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(service) as response:
                        if response.status == 200:
                            if service.endswith('json'):
                                data = await response.json()
                                return data['ip']
                            else:
                                return (await response.text()).strip()
            except Exception as e:
                self.logger.warning(f"IP service {service} failed: {e}")
        return None

    async def _get_cached_ip(self) -> Optional[str]:
        """Get cached IP address if still valid"""
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text())
                if time.time() - data['timestamp'] < self.update_interval:
                    return data['ip']
            except Exception as e:
                self.logger.warning(f"Error reading cache: {e}")
        return None

    async def _cache_ip(self, ip: str) -> None:
        """Cache the current IP address"""
        try:
            self.cache_file.write_text(json.dumps({
                'ip': ip,
                'timestamp': time.time()
            }))
        except Exception as e:
            self.logger.warning(f"Error writing cache: {e}")

    async def _update_ddns_record(self, ip: str) -> bool:
        """Update DDNS record with new IP"""
        try:
            response = await self._make_ddns_request(ip)
            return response.status == 200
        except Exception as e:
            self.logger.error(f"DDNS update failed: {e}")
            return False

    async def _verify_dns_propagation(self) -> bool:
        """Verify DNS propagation across multiple nameservers"""
        nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
        hostname = self.config['hostname']

        for ns in nameservers:
            try:
                self.resolver.nameservers = [ns]
                result = await self.resolver.query(hostname, 'A')
                if result and result[0].host == self.current_ip:
                    continue
                return False
            except Exception as e:
                self.logger.warning(f"DNS verification failed for {ns}: {e}")
                return False
        return True
    

class ConnectionMonitor:
    """
    Enhanced connection monitor with better resource management and metrics
    """
    def __init__(self, max_history: int = 1000, logger: logging.Logger = None):
        self.max_history = max_history
        self.connection_history: List[Dict] = []
        self.active_connections: Dict[str, Dict] = {}
        self.metrics = ConnectionMetrics()
        self.logger = logger or logging.getLogger('ConnectionMonitor')
        self._cleanup_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()

    async def start(self):
        """Start monitoring with periodic cleanup"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def stop(self):
        """Stop monitoring and cleanup resources"""
        self._stop_event.set()
        if self._cleanup_task:
            await self._cleanup_task
            self._cleanup_task = None

    async def _periodic_cleanup(self):
        """Periodically clean up old connection records"""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(300)  # Clean every 5 minutes
                await self._cleanup_old_records()
            except Exception as e:
                self.logger.error(f"Cleanup error: {e}")

    async def _cleanup_old_records(self):
        """Clean up old connection records"""
        now = datetime.now()
        cutoff = now - timedelta(days=7)  # Keep 7 days of history

        # Clean connection history
        self.connection_history = [
            record for record in self.connection_history
            if datetime.fromisoformat(record['timestamp']) > cutoff
        ]

        # Clean active connections
        closed = []
        for conn_id, conn in self.active_connections.items():
            if now - conn['last_seen'] > timedelta(minutes=5):
                closed.append(conn_id)

        for conn_id in closed:
            await self.close_connection(conn_id)

    async def add_connection(self, remote_host: str, port: int) -> str:
        """Add new connection for monitoring"""
        conn_id = self._generate_connection_id(remote_host, port)
        
        self.active_connections[conn_id] = {
            'remote_host': remote_host,
            'port': port,
            'started_at': datetime.now(),
            'last_seen': datetime.now(),
            'bytes_sent': 0,
            'bytes_received': 0,
            'latency_ms': []
        }

        # Add to history with rotation
        self.connection_history.append({
            'connection_id': conn_id,
            'remote_host': remote_host,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'event': 'connected'
        })

        if len(self.connection_history) > self.max_history:
            self.connection_history = self.connection_history[-self.max_history:]

        await self.metrics.record_connection_started()
        return conn_id

    async def update_connection_stats(self, conn_id: str, 
                                    bytes_sent: int, 
                                    bytes_received: int, 
                                    latency_ms: float):
        """Update connection statistics"""
        if conn_id in self.active_connections:
            conn = self.active_connections[conn_id]
            conn['last_seen'] = datetime.now()
            conn['bytes_sent'] += bytes_sent
            conn['bytes_received'] += bytes_received
            conn['latency_ms'].append(latency_ms)

            # Keep only last 100 latency measurements
            if len(conn['latency_ms']) > 100:
                conn['latency_ms'] = conn['latency_ms'][-100:]

            await self.metrics.record_traffic(bytes_sent, bytes_received)

    async def close_connection(self, conn_id: str):
        """Close and cleanup connection"""
        if conn_id in self.active_connections:
            conn = self.active_connections.pop(conn_id)
            
            self.connection_history.append({
                'connection_id': conn_id,
                'remote_host': conn['remote_host'],
                'port': conn['port'],
                'timestamp': datetime.now().isoformat(),
                'event': 'disconnected',
                'duration_seconds': (datetime.now() - conn['started_at']).total_seconds(),
                'total_bytes_sent': conn['bytes_sent'],
                'total_bytes_received': conn['bytes_received'],
                'average_latency_ms': sum(conn['latency_ms']) / len(conn['latency_ms']) 
                                    if conn['latency_ms'] else 0
            })

            await self.metrics.record_connection_closed()

    def _generate_connection_id(self, remote_host: str, port: int) -> str:
        """Generate unique connection ID"""
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        return hashlib.sha256(f"{timestamp}{remote_host}{port}".encode()).hexdigest()[:12]

class TunnelManager:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('TunnelManager')
        self.setup_logging()  # Changed to setup_logging for consistency with Python naming conventions
        self.nat = NATTraversal(self.logger)
        self.ddns = EnhancedDDNS(config, self.logger)
        self.monitor = ConnectionMonitor(max_history=1000, logger=self.logger)  # Pass logger explicitly
        self.tunnel_process = None
        self._setup_security_options()
        
    def setup_logging(self):
        """Setup logging for the TunnelManager"""
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)  # or from config if available
        
    def _setup_security_options(self):
        """Setup enhanced security options"""
        self.ssh_options = [
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=~/.ssh/known_hosts',
            '-o', 'ServerAliveInterval=30',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'PasswordAuthentication=no',
            '-o', 'PubkeyAuthentication=yes',
            '-o', 'HostKeyAlgorithms=ssh-ed25519,ssh-rsa',
            '-o', 'KexAlgorithms=curve25519-sha256@libssh.org,diffie-hellman-group16-sha512',
            '-o', 'Ciphers=chacha20-poly1305@openssh.com,aes256-gcm@openssh.com'
        ]

    async def start_tunnel(self, remote_host: str, port: int = 22):
        try:
            await self.nat.initialize()
            conn_info = await self.nat.get_connection_info(port)
            
            if not self._validate_connection_info(conn_info):
                raise TunnelError("Invalid connection information")

            self.tunnel_process = await self._create_tunnel_process(
                conn_info, remote_host, port
            )
            
            # Start connection monitoring
            monitor_task = asyncio.create_task(
                self.monitor.monitor_connection(remote_host, port)  # Ensure this method is awaitable
            )
            
            # Start tunnel monitoring
            tunnel_task = asyncio.create_task(
                self._monitor_tunnel_process(self.tunnel_process)
            )
            
            await asyncio.gather(monitor_task, tunnel_task)
            
        except Exception as e:
            self.logger.error(f"Tunnel start failed: {e}")
            raise
    
    def _validate_connection_info(self, conn_info: ConnectionInfo) -> bool:
        """Validate connection information"""
        required_fields = ['local_ip', 'public_ip', 'mapped_port']
        return all(hasattr(conn_info, field) for field in required_fields)

    async def _start_direct_tunnel(self, conn_info: ConnectionInfo, remote_host: str, port: int) -> None:
        """Start a direct tunnel using SSH"""
        cmd = [
            'ssh',
            '-NTC',
            '-o', 'ServerAliveInterval=60',
            '-o', 'ServerAliveCountMax=3',
            '-o', 'ExitOnForwardFailure=yes',
            '-o', f'Port={port}',
            f'{remote_host}'
        ]

        if conn_info.tunnel_type == TunnelType.UPNP:
            cmd.extend(['-R', f'{conn_info.mapped_port}:localhost:{port}'])
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        await self._monitor_process(process)


    async def monitor_connection(self, remote_host: str, port: int):
        """Monitor tunnel connection and handle reconnection"""
        while not self.stop_event.is_set():
            try:
                reader, writer = await asyncio.open_connection(remote_host, port, limit=1)
                writer.close()
                await writer.wait_closed()
                await asyncio.sleep(10)
            except Exception as e:
                self.logger.error(f"Connection lost: {e}")
                await self._handle_reconnection(remote_host, port)

    async def _handle_reconnection(self, remote_host: str, port: int):
        """Handle tunnel reconnection with exponential backoff"""
        retry_count = 0
        max_retries = self.config.get('max_retries', 5)
        base_delay = self.config.get('base_delay', 5)

        while retry_count < max_retries and not self.stop_event.is_set():
            try:
                delay = base_delay * (2 ** retry_count)
                self.logger.info(f"Attempting reconnection in {delay} seconds...")
                await asyncio.sleep(delay)
                
                await self.start_tunnel(remote_host, port)
                self.logger.info("Reconnection successful")
                return
                
            except Exception as e:
                self.logger.error(f"Reconnection attempt {retry_count + 1} failed: {e}")
                retry_count += 1

        if retry_count >= max_retries:
            self.logger.error("Max reconnection attempts reached")
            self.stop()
            
    async def _monitor_process(self, process: asyncio.subprocess.Process) -> None:
        """Monitor the tunnel process"""
        while True:
            try:
                line = await process.stderr.readline()
                if not line:
                    break
                self.logger.debug(line.decode().strip())
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                break

    def stop(self) -> None:
        """Stop the tunnel and cleanup"""
        self.stop_event.set()
        if self.connection_monitor:
            self.connection_monitor.join()
        self.nat.cleanup()


class CommandLineParser:
    """Handles command line argument parsing with subcommands"""
    
    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description='P2P SSH Tunnel with NAT Traversal',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Global arguments
        parser.add_argument(
            '--config',
            type=Path,
            default=Path.home() / '.ssh' / 'p2p_tunnel.json',
            help='Path to config file'
        )
        parser.add_argument(
            '--log-level',
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
            default='INFO',
            help='Set logging level'
        )
        
        # Create subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Setup command
        CommandLineParser._add_setup_parser(subparsers)
        
        # Connect command
        CommandLineParser._add_connect_parser(subparsers)
        
        # Key management command
        CommandLineParser._add_key_management_parser(subparsers)
        
        # DDNS command
        CommandLineParser._add_ddns_parser(subparsers)
        
        return parser
    
    @staticmethod
    def _add_setup_parser(subparsers: argparse._SubParsersAction) -> None:
        setup_parser = subparsers.add_parser('setup', help='Initial tunnel setup')
        setup_parser.add_argument(
            '--key-type',
            choices=['ed25519', 'rsa', 'ecdsa'],
            default='ed25519',
            help='SSH key type'
        )
        setup_parser.add_argument(
            '--force',
            action='store_true',
            help='Force overwrite existing configuration'
        )
    
    @staticmethod
    def _add_connect_parser(subparsers: argparse._SubParsersAction) -> None:
        connect_parser = subparsers.add_parser('connect', help='Connect to remote host')
        connect_parser.add_argument('remote_host', help='Remote host to connect to')
        connect_parser.add_argument(
            '--port',
            type=int,
            default=22,
            help='Remote SSH port'
        )
        connect_parser.add_argument(
            '--reverse',
            action='store_true',
            help='Create reverse tunnel'
        )
        connect_parser.add_argument(
            '--timeout',
            type=int,
            default=30,
            help='Connection timeout in seconds'
        )
    
    @staticmethod
    def _add_key_management_parser(subparsers: argparse._SubParsersAction) -> None:
        key_parser = subparsers.add_parser('keys', help='Key management')
        key_group = key_parser.add_mutually_exclusive_group(required=True)
        key_group.add_argument(
            '--add',
            metavar='PUBLIC_KEY',
            help='Add public key'
        )
        key_group.add_argument(
            '--remove',
            metavar='FINGERPRINT',
            help='Remove key by fingerprint'
        )
        key_group.add_argument(
            '--list',
            action='store_true',
            help='List all keys'
        )
    
    @staticmethod
    def _add_ddns_parser(subparsers: argparse._SubParsersAction) -> None:
        ddns_parser = subparsers.add_parser('ddns', help='DDNS management')
        ddns_parser.add_argument('--provider', required=True, help='DDNS provider')
        ddns_parser.add_argument('--hostname', required=True, help='DDNS hostname')
        ddns_parser.add_argument('--username', help='DDNS username')
        ddns_parser.add_argument('--password', help='DDNS password')
        


class LoggingSetup:
    @staticmethod
    def setup_logging(level: str, log_file: Path) -> logging.Logger:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Create formatters
        file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        
        # Create handlers
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(file_formatter)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(console_formatter)
        
        # Setup logger
        logger = logging.getLogger('P2PTunnel')
        logger.setLevel(getattr(logging, level))
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
class CommandHandler:
    """Handles execution of different commands"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Initialize managers
        self.system_info = self._get_system_info()
        self.security_manager = SecurityManager(Path.home() / '.ssh', self.logger)
        self.network_manager = NetworkManager(self.system_info)
        self.key_manager = KeyManager(TunnelConfig(Path.home() / '.ssh' / 'p2p_tunnel.json'))  # Initialize KeyManager
        self.tunnel_manager = TunnelManager(config)
    
    @staticmethod
    def _get_system_info() -> SystemInfo:
        return SystemInfo(
            platform=platform.system(),
            is_wsl='Microsoft' in platform.uname().release,
            firewall_type=detect_firewall_type(),
            arch=platform.machine(),
            python_version=platform.python_version()
        )
    
    async def handle_setup(self, args: argparse.Namespace) -> None:
        """Handle setup command"""
        try:
            # Generate SSH key
            key_path = self.key_manager.generate_key(
                key_type=args.key_type  # Removed await since generate_key is not async
            )
            self.logger.info(f"Generated {args.key_type} key pair at {key_path}")
            
            # Configure firewall
            port = self.config['ssh_port']
            self.network_manager.configure_firewall(port)
            self.logger.info(f"Configured firewall for port {port}")
            
            # Get network information
            net_info = self.network_manager.get_network_info()
            self.logger.info(f"Local IP: {net_info.local_ip}")
            if net_info.public_ip:
                self.logger.info(f"Public IP: {net_info.public_ip}")
                
        except Exception as e:
            self.logger.error(f"Setup failed: {e}")
            raise
    
    async def handle_connect(self, args: argparse.Namespace) -> None:
        """Handle connect command"""
        try:
            # Verify connectivity
            if not await self.network_manager.test_connectivity(
                args.remote_host,
                args.port,
                timeout=args.timeout
            ):
                raise TunnelError("Unable to reach remote host")
            
            # Start tunnel
            if args.reverse:
                await self.tunnel_manager.start_reverse_tunnel(
                    args.remote_host,
                    args.port
                )
            else:
                await self.tunnel_manager.start_tunnel(
                    args.remote_host,
                    args.port
                )
            
            self.logger.info(f"Connected to {args.remote_host}:{args.port}")
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise
    
    async def handle_keys(self, args: argparse.Namespace) -> None:
        """Handle key management command"""
        try:
            if args.add:
                await self.security_manager.add_authorized_key(args.add)
                self.logger.info("Public key added successfully")
                
            elif args.remove:
                await self.security_manager.remove_authorized_key(args.remove)
                self.logger.info("Public key removed successfully")
                
            elif args.list:
                keys = await self.security_manager.list_keys()
                for key in keys:
                    print(f"\nFingerprint: {key.fingerprint}")
                    print(f"Type: {key.key_type}")
                    print(f"Added: {key.added_date}")
                    if key.comment:
                        print(f"Comment: {key.comment}")
                    
        except Exception as e:
            self.logger.error(f"Key management failed: {e}")
            raise
    
    async def handle_ddns(self, args: argparse.Namespace) -> None:
        """Handle DDNS command"""
        try:
            ddns_config = {
                'provider': args.provider,
                'hostname': args.hostname,
                'username': args.username,
                'password': args.password
            }
            
            ddns = EnhancedDDNS(ddns_config, self.logger)
            if await ddns.update():
                self.logger.info("DDNS updated successfully")
            else:
                raise TunnelError("DDNS update failed")
                
        except Exception as e:
            self.logger.error(f"DDNS management failed: {e}")
            raise


async def main() -> None:
    """
    Enhanced main function with better organization and error handling
    """
    async def load_config(config_path: Path) -> Dict[str, Any]:
            """Loads configuration from the specified path."""
            config_manager = ConfigManager(config_path=config_path)
            return config_manager.config
    try:
        # Parse command line arguments
        parser = CommandLineParser.create_parser()
        args = parser.parse_args()
        
        # Setup logging
        logger = LoggingSetup.setup_logging(
            args.log_level,
            Path.home() / '.ssh' / 'p2p_tunnel.log'
        )
        
                
        # Load configuration
        config = await load_config(args.config)
        
        # Initialize command handler
        handler = CommandHandler(config, logger)
        
        # Execute command
        if args.command == 'setup':
            await handler.handle_setup(args)
        elif args.command == 'connect':
            await handler.handle_connect(args)
        elif args.command == 'keys':
            await handler.handle_keys(args)
        elif args.command == 'ddns':
            await handler.handle_ddns(args)
        else:
            parser.print_help()
            sys.exit(1)
        
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        await cleanup_resources()
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Error: {str(e)}", exc_info=True)
        sys.exit(1)

def detect_firewall_type() -> Optional[str]:
    """Detect system firewall type"""
    if platform.system() == "Linux":
        if shutil.which('ufw'):
            return 'ufw'
        elif shutil.which('firewalld'):
            return 'firewalld'
        elif shutil.which('iptables'):
            return 'iptables'
    elif platform.system() == "Darwin":
        return 'pf'
    elif platform.system() == "Windows":
        return 'windows'
    return None

async def cleanup_resources() -> None:
    """Clean up resources before exit"""
    # Implementation would depend on what resources need cleanup
    pass

if __name__ == '__main__':
    asyncio.run(main())
