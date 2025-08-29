# utils/firewall.py
import ipaddress
from typing import Set, List, Optional, Callable
import socket
import logging
from datetime import datetime, timedelta

class Firewall:
    def __init__(self):
        self.allowed_ips: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self.rate_limits: dict = {}
        self.rate_limit_window = timedelta(seconds=60)
        self.max_requests_per_minute = 100
        self.custom_rules: List[Callable[[str], bool]] = []
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("Firewall")

    def allow_ip(self, ip: str) -> None:
        try:
            validated_ip = str(ipaddress.ip_address(ip))
            self.allowed_ips.add(validated_ip)
            self.logger.info(f"Allowed IP: {validated_ip}")
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip}")

    def block_ip(self, ip: str) -> None:
        try:
            validated_ip = str(ipaddress.ip_address(ip))
            self.blocked_ips.add(validated_ip)
            self.logger.info(f"Blocked IP: {validated_ip}")
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip}")

    def add_cidr_range(self, cidr: str, allow: bool = True) -> None:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            if allow:
                self.allowed_ips.update(str(ip) for ip in network.hosts())
            else:
                self.blocked_ips.update(str(ip) for ip in network.hosts())
            self.logger.info(f"{'Allowed' if allow else 'Blocked'} CIDR: {cidr}")
        except ValueError:
            self.logger.warning(f"Invalid CIDR range: {cidr}")

    def add_custom_rule(self, rule_func: Callable[[str], bool]) -> None:
        self.custom_rules.append(rule_func)

    def check_rate_limit(self, ip: str) -> bool:
        now = datetime.now()
        if ip in self.rate_limits:
            count, last_time = self.rate_limits[ip]
            if now - last_time < self.rate_limit_window:
                if count >= self.max_requests_per_minute:
                    self.logger.warning(f"Rate limit exceeded for IP: {ip}")
                    return False
                self.rate_limits[ip] = (count + 1, last_time)
            else:
                self.rate_limits[ip] = (1, now)
        else:
            self.rate_limits[ip] = (1, now)
        
        return True

    def is_allowed(self, ip: str) -> bool:
        try:
            validated_ip = str(ipaddress.ip_address(ip))
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip}")
            return False

        if validated_ip in self.blocked_ips:
            self.logger.warning(f"Blocked IP attempted connection: {validated_ip}")
            return False

        if self.allowed_ips and validated_ip not in self.allowed_ips:
            self.logger.warning(f"IP not in allowed list: {validated_ip}")
            return False

        if not self.check_rate_limit(validated_ip):
            return False

        for rule in self.custom_rules:
            if not rule(validated_ip):
                self.logger.warning(f"IP failed custom rule: {validated_ip}")
                return False

        return True

    def load_config_from_file(self, config_path: str) -> None:
        try:
            with open(config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    action, target = parts[0], parts[1]
                    
                    if action == 'allow':
                        if '/' in target:
                            self.add_cidr_range(target, allow=True)
                        else:
                            self.allow_ip(target)
                    elif action == 'block':
                        if '/' in target:
                            self.add_cidr_range(target, allow=False)
                        else:
                            self.block_ip(target)
        
        except FileNotFoundError:
            self.logger.warning(f"Firewall config file not found: {config_path}")
        except Exception as e:
            self.logger.error(f"Error loading firewall config: {e}")

# Global firewall instance
firewall = Firewall()