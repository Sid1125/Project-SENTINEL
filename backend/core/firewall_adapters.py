import logging
import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    from core.system_integration import is_running_as_admin
except ModuleNotFoundError:
    from backend.core.system_integration import is_running_as_admin

logger = logging.getLogger(__name__)


@dataclass
class FirewallOperationResult:
    success: bool
    adapter: str
    action: str
    ip: str
    message: str = ""
    commands: Optional[List[List[str]]] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "success": self.success,
            "adapter": self.adapter,
            "action": self.action,
            "ip": self.ip,
            "message": self.message,
            "commands": self.commands or [],
        }


class FirewallAdapter:
    name = "unsupported"

    def supports_platform(self) -> bool:
        return False

    def is_available(self) -> bool:
        return False

    def diagnostics(self) -> Dict[str, object]:
        return {
            "adapter": self.name,
            "platform": platform.system(),
            "supported": self.supports_platform(),
            "available": self.is_available(),
            "admin": is_running_as_admin(),
            "quarantine_profiles": self.supported_quarantine_profiles(),
        }

    def block_ip(self, ip: str) -> FirewallOperationResult:
        return FirewallOperationResult(False, self.name, "block", ip, "Adapter not supported")

    def unblock_ip(self, ip: str) -> FirewallOperationResult:
        return FirewallOperationResult(False, self.name, "unblock", ip, "Adapter not supported")

    def quarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        result = self.block_ip(ip)
        result.action = "quarantine"
        port_suffix = f" ports={','.join(str(port) for port in ports)}" if ports else ""
        target_suffix = ""
        if allowed_networks or allowed_destinations:
            target_suffix = f" allow={','.join((allowed_networks or []) + (allowed_destinations or []))}"
        result.message = f"{result.message} [{profile}/{scope}{port_suffix}{target_suffix}]".strip()
        return result

    def unquarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        result = self.unblock_ip(ip)
        result.action = "unquarantine"
        port_suffix = f" ports={','.join(str(port) for port in ports)}" if ports else ""
        target_suffix = ""
        if allowed_networks or allowed_destinations:
            target_suffix = f" allow={','.join((allowed_networks or []) + (allowed_destinations or []))}"
        result.message = f"{result.message} [{profile}/{scope}{port_suffix}{target_suffix}]".strip()
        return result

    def get_blocked_ips(self) -> List[str]:
        return []

    def supported_quarantine_profiles(self) -> List[str]:
        return ["full_isolation"]


class WindowsFirewallAdapter(FirewallAdapter):
    name = "windows_firewall"

    def supports_platform(self) -> bool:
        return platform.system() == "Windows"

    def is_available(self) -> bool:
        return self.supports_platform() and shutil.which("netsh") is not None

    def _rule_name(self, ip: str, direction: str) -> str:
        suffix = ip.replace(".", "_").replace(":", "_")
        return f"SENTINEL_BLOCK_{direction.upper()}_{suffix}"

    def _run(self, command: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(command, check=True, capture_output=True, text=True)

    def supported_quarantine_profiles(self) -> List[str]:
        return ["restricted_network", "full_isolation", "critical_service_isolation", "defensive_lockdown"]

    def block_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "block", ip, "netsh is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "block", ip, "Administrator privileges required")

        commands = [
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self._rule_name(ip, 'in')}",
                "dir=in",
                "action=block",
                f"remoteip={ip}",
            ],
            [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self._rule_name(ip, 'out')}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
            ],
        ]

        try:
            for command in commands:
                self._run(command)
            return FirewallOperationResult(True, self.name, "block", ip, "Windows Firewall rules added", commands)
        except Exception as exc:
            logger.error(f"Windows firewall block failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "block", ip, str(exc), commands)

    def quarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "netsh is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "Administrator privileges required")

        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        normalized_networks = sorted(set(allowed_networks or []))
        normalized_destinations = sorted(set(allowed_destinations or []))
        commands = []

        if profile == "critical_service_isolation" and normalized_ports:
            local_ports = ",".join(str(port) for port in sorted(set(normalized_ports)))
            commands.append(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={self._rule_name(ip, 'critical_in')}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=TCP",
                    f"localport={local_ports}",
                ]
            )
        else:
            commands.append(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={self._rule_name(ip, 'in')}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                ]
            )
            if profile in {"full_isolation", "defensive_lockdown"}:
                commands.append(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={self._rule_name(ip, 'out')}",
                        "dir=out",
                        "action=block",
                        f"remoteip={ip}",
                    ]
                )

        try:
            for command in commands:
                self._run(command)
            message = "Windows Firewall quarantine rules added"
            port_suffix = f" ports={','.join(str(port) for port in normalized_ports)}" if normalized_ports else ""
            allow_suffix = ""
            if normalized_networks or normalized_destinations:
                allow_suffix = f" allow={','.join(normalized_networks + normalized_destinations)}"
            return FirewallOperationResult(True, self.name, "quarantine", ip, f"{message} [{profile}/{scope}{port_suffix}{allow_suffix}]", commands)
        except Exception as exc:
            logger.error(f"Windows firewall quarantine failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "quarantine", ip, str(exc), commands)

    def unblock_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "unblock", ip, "netsh is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "unblock", ip, "Administrator privileges required")

        commands = [
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={self._rule_name(ip, 'in')}",
            ],
            [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={self._rule_name(ip, 'out')}",
            ],
        ]

        try:
            for command in commands:
                subprocess.run(command, capture_output=True, text=True)
            return FirewallOperationResult(True, self.name, "unblock", ip, "Windows Firewall rules removed", commands)
        except Exception as exc:
            logger.error(f"Windows firewall unblock failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "unblock", ip, str(exc), commands)

    def get_blocked_ips(self) -> List[str]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            blocked = []
            for line in result.stdout.splitlines():
                if "Rule Name:" in line and "SENTINEL_BLOCK_" in line:
                    rule_name = line.split(":", 1)[1].strip()
                    parts = rule_name.split("_")
                    if len(parts) >= 5:
                        blocked.append(".".join(parts[4:]))
            return sorted(set(blocked))
        except Exception as exc:
            logger.error(f"Failed to enumerate Windows firewall rules: {exc}")
            return []


class LinuxIptablesAdapter(FirewallAdapter):
    name = "linux_iptables"

    def supports_platform(self) -> bool:
        return platform.system() != "Windows"

    def is_available(self) -> bool:
        return self.supports_platform() and shutil.which("iptables") is not None

    def _run(self, command: List[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(command, check=check, capture_output=True, text=True)

    def supported_quarantine_profiles(self) -> List[str]:
        return ["restricted_network", "segment_isolation", "full_isolation", "critical_service_isolation"]

    def _rule_exists(self, chain: str, ip: str, direction: str) -> bool:
        target_flag = "-s" if direction == "src" else "-d"
        try:
            self._run(["iptables", "-C", chain, target_flag, ip, "-j", "DROP"])
            return True
        except Exception:
            return False

    def _service_rule_exists(self, chain: str, ip: str, ports: List[int]) -> bool:
        try:
            self._run(
                [
                    "iptables", "-C", chain, "-s", ip, "-p", "tcp",
                    "-m", "multiport", "--dports", ",".join(str(port) for port in ports),
                    "-j", "DROP",
                ]
            )
            return True
        except Exception:
            return False

    def _custom_rule_exists(self, command: List[str]) -> bool:
        try:
            check_command = command.copy()
            check_command[1] = "-C"
            self._run(check_command)
            return True
        except Exception:
            return False

    def block_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "block", ip, "iptables is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "block", ip, "Root privileges required")

        commands = []
        try:
            if not self._rule_exists("INPUT", ip, "src"):
                commands.append(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            if not self._rule_exists("OUTPUT", ip, "dst"):
                commands.append(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])

            for command in commands:
                self._run(command)

            message = "iptables rules added" if commands else "iptables rules already present"
            return FirewallOperationResult(True, self.name, "block", ip, message, commands)
        except Exception as exc:
            logger.error(f"iptables block failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "block", ip, str(exc), commands)

    def quarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "iptables is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "Root privileges required")

        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        normalized_networks = sorted(set(allowed_networks or []))
        normalized_destinations = sorted(set(allowed_destinations or []))
        commands = []
        try:
            if profile == "critical_service_isolation" and normalized_ports:
                if not self._service_rule_exists("INPUT", ip, normalized_ports):
                    commands.append(
                        [
                            "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp",
                            "-m", "multiport", "--dports", ",".join(str(port) for port in normalized_ports),
                            "-j", "DROP",
                        ]
                    )
            elif profile in {"restricted_network", "segment_isolation"} and (normalized_networks or normalized_destinations):
                for target in normalized_networks + normalized_destinations:
                    allow_command = ["iptables", "-A", "FORWARD", "-s", ip, "-d", target, "-j", "ACCEPT"]
                    if not self._custom_rule_exists(allow_command):
                        commands.append(allow_command)
                drop_command = ["iptables", "-A", "FORWARD", "-s", ip, "-j", "DROP"]
                if not self._custom_rule_exists(drop_command):
                    commands.append(drop_command)
            else:
                if not self._rule_exists("INPUT", ip, "src"):
                    commands.append(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
                if profile == "full_isolation" and not self._rule_exists("OUTPUT", ip, "dst"):
                    commands.append(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])

            for command in commands:
                self._run(command)

            message = "iptables quarantine rules added" if commands else "iptables quarantine rules already present"
            port_suffix = f" ports={','.join(str(port) for port in normalized_ports)}" if normalized_ports else ""
            allow_suffix = ""
            if normalized_networks or normalized_destinations:
                allow_suffix = f" allow={','.join(normalized_networks + normalized_destinations)}"
            return FirewallOperationResult(True, self.name, "quarantine", ip, f"{message} [{profile}/{scope}{port_suffix}{allow_suffix}]", commands)
        except Exception as exc:
            logger.error(f"iptables quarantine failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "quarantine", ip, str(exc), commands)

    def unquarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "unquarantine", ip, "iptables is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "unquarantine", ip, "Root privileges required")

        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        normalized_networks = sorted(set(allowed_networks or []))
        normalized_destinations = sorted(set(allowed_destinations or []))
        commands: List[List[str]] = []

        if profile == "critical_service_isolation" and normalized_ports:
            commands.append(
                [
                    "iptables", "-D", "INPUT", "-s", ip, "-p", "tcp",
                    "-m", "multiport", "--dports", ",".join(str(port) for port in normalized_ports),
                    "-j", "DROP",
                ]
            )
        elif profile in {"restricted_network", "segment_isolation"} and (normalized_networks or normalized_destinations):
            for target in normalized_networks + normalized_destinations:
                commands.append(["iptables", "-D", "FORWARD", "-s", ip, "-d", target, "-j", "ACCEPT"])
            commands.append(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
        else:
            commands.extend([
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
            ])

        try:
            for command in commands:
                self._run(command, check=False)
            return FirewallOperationResult(True, self.name, "unquarantine", ip, "iptables quarantine rules removed", commands)
        except Exception as exc:
            logger.error(f"iptables unquarantine failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "unquarantine", ip, str(exc), commands)

    def unblock_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "unblock", ip, "iptables is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "unblock", ip, "Root privileges required")

        commands = [
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
        ]

        try:
            for command in commands:
                self._run(command, check=False)
            return FirewallOperationResult(True, self.name, "unblock", ip, "iptables rules removed", commands)
        except Exception as exc:
            logger.error(f"iptables unblock failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "unblock", ip, str(exc), commands)

    def get_blocked_ips(self) -> List[str]:
        if not self.is_available():
            return []
        try:
            result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, timeout=10)
            blocked = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "DROP":
                    blocked.append(parts[3])
            return sorted(set(blocked))
        except Exception as exc:
            logger.error(f"Failed to enumerate iptables rules: {exc}")
            return []


class LinuxNftablesAdapter(FirewallAdapter):
    name = "linux_nftables"

    def supports_platform(self) -> bool:
        return platform.system() != "Windows"

    def is_available(self) -> bool:
        return self.supports_platform() and shutil.which("nft") is not None

    def _run(self, command: List[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(command, check=check, capture_output=True, text=True)

    def supported_quarantine_profiles(self) -> List[str]:
        return ["restricted_network", "segment_isolation", "full_isolation", "critical_service_isolation"]

    def _ensure_table_and_chain(self):
        self._run(["nft", "add", "table", "inet", "sentinel"], check=False)
        self._run(
            [
                "nft",
                "add",
                "chain",
                "inet",
                "sentinel",
                "sentinel_block",
                "{",
                "type",
                "filter",
                "hook",
                "input",
                "priority",
                "0",
                ";",
                "}",
            ],
            check=False,
        )

    def block_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "block", ip, "nft is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "block", ip, "Root privileges required")

        commands = [
            ["nft", "add", "table", "inet", "sentinel"],
            ["nft", "add", "chain", "inet", "sentinel", "sentinel_block", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"],
            ["nft", "add", "rule", "inet", "sentinel", "sentinel_block", "ip", "saddr", ip, "drop"],
        ]
        try:
            self._ensure_table_and_chain()
            self._run(commands[2])
            return FirewallOperationResult(True, self.name, "block", ip, "nftables rule added", commands)
        except Exception as exc:
            logger.error(f"nftables block failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "block", ip, str(exc), commands)

    def quarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "nft is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "Root privileges required")

        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        commands = []
        if profile == "critical_service_isolation" and normalized_ports:
            commands.append(
                [
                    "nft", "add", "rule", "inet", "sentinel", "sentinel_block",
                    "ip", "saddr", ip, "tcp", "dport", "{",
                    ",".join(str(port) for port in normalized_ports),
                    "}", "drop",
                ]
            )
        else:
            commands.append(["nft", "add", "rule", "inet", "sentinel", "sentinel_block", "ip", "saddr", ip, "drop"])
        if profile == "full_isolation":
            commands.append(["nft", "add", "rule", "inet", "sentinel", "sentinel_block", "ip", "daddr", ip, "drop"])

        try:
            self._ensure_table_and_chain()
            for command in commands:
                self._run(command)
            port_suffix = f" ports={','.join(str(port) for port in normalized_ports)}" if normalized_ports else ""
            return FirewallOperationResult(True, self.name, "quarantine", ip, f"nftables quarantine rule added [{profile}/{scope}{port_suffix}]", commands)
        except Exception as exc:
            logger.error(f"nftables quarantine failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "quarantine", ip, str(exc), commands)

    def unblock_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "unblock", ip, "nft is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "unblock", ip, "Root privileges required")

        command = ["nft", "delete", "rule", "inet", "sentinel", "sentinel_block", "ip", "saddr", ip, "drop"]
        try:
            self._run(command, check=False)
            return FirewallOperationResult(True, self.name, "unblock", ip, "nftables rule removal requested", [command])
        except Exception as exc:
            logger.error(f"nftables unblock failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "unblock", ip, str(exc), [command])

    def get_blocked_ips(self) -> List[str]:
        if not self.is_available():
            return []
        try:
            result = self._run(["nft", "list", "chain", "inet", "sentinel", "sentinel_block"], check=False)
            blocked = []
            for line in result.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[0] == "ip" and parts[1] == "saddr":
                    blocked.append(parts[2])
            return sorted(set(blocked))
        except Exception as exc:
            logger.error(f"Failed to enumerate nftables rules: {exc}")
            return []


class LinuxUfwAdapter(FirewallAdapter):
    name = "linux_ufw"

    def supports_platform(self) -> bool:
        return platform.system() != "Windows"

    def is_available(self) -> bool:
        return self.supports_platform() and shutil.which("ufw") is not None

    def _run(self, command: List[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(command, check=check, capture_output=True, text=True)

    def supported_quarantine_profiles(self) -> List[str]:
        return ["restricted_network", "segment_isolation", "full_isolation", "defensive_lockdown"]

    def block_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "block", ip, "ufw is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "block", ip, "Root privileges required")

        commands = [["ufw", "deny", "from", ip]]
        try:
            self._run(commands[0])
            return FirewallOperationResult(True, self.name, "block", ip, "UFW deny rule added", commands)
        except Exception as exc:
            logger.error(f"UFW block failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "block", ip, str(exc), commands)

    def quarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "ufw is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "quarantine", ip, "Root privileges required")

        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        normalized_networks = sorted(set(allowed_networks or []))
        normalized_destinations = sorted(set(allowed_destinations or []))
        commands = []
        if profile == "critical_service_isolation" and normalized_ports:
            for port in normalized_ports:
                commands.append(["ufw", "deny", "proto", "tcp", "from", ip, "to", "any", "port", str(port)])
        elif profile in {"restricted_network", "segment_isolation"} and (normalized_networks or normalized_destinations):
            for target in normalized_networks + normalized_destinations:
                commands.append(["ufw", "route", "allow", "from", ip, "to", target])
            commands.append(["ufw", "route", "deny", "from", ip])
        else:
            commands.append(["ufw", "deny", "from", ip])
        if profile == "full_isolation":
            commands.append(["ufw", "deny", "out", "to", ip])

        try:
            for command in commands:
                self._run(command)
            port_suffix = f" ports={','.join(str(port) for port in normalized_ports)}" if normalized_ports else ""
            allow_suffix = ""
            if normalized_networks or normalized_destinations:
                allow_suffix = f" allow={','.join(normalized_networks + normalized_destinations)}"
            return FirewallOperationResult(True, self.name, "quarantine", ip, f"UFW quarantine rule added [{profile}/{scope}{port_suffix}{allow_suffix}]", commands)
        except Exception as exc:
            logger.error(f"UFW quarantine failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "quarantine", ip, str(exc), commands)

    def unquarantine_ip(
        self,
        ip: str,
        profile: str = "full_isolation",
        scope: str = "all_traffic",
        ports: Optional[List[int]] = None,
        allowed_networks: Optional[List[str]] = None,
        allowed_destinations: Optional[List[str]] = None,
    ) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "unquarantine", ip, "ufw is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "unquarantine", ip, "Root privileges required")

        normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})
        normalized_networks = sorted(set(allowed_networks or []))
        normalized_destinations = sorted(set(allowed_destinations or []))
        commands: List[List[str]] = []

        if profile == "critical_service_isolation" and normalized_ports:
            for port in normalized_ports:
                commands.append(["ufw", "--force", "delete", "deny", "proto", "tcp", "from", ip, "to", "any", "port", str(port)])
        elif profile in {"restricted_network", "segment_isolation"} and (normalized_networks or normalized_destinations):
            for target in normalized_networks + normalized_destinations:
                commands.append(["ufw", "--force", "delete", "route", "allow", "from", ip, "to", target])
            commands.append(["ufw", "--force", "delete", "route", "deny", "from", ip])
        else:
            commands.append(["ufw", "--force", "delete", "deny", "from", ip])
            if profile == "full_isolation":
                commands.append(["ufw", "--force", "delete", "deny", "out", "to", ip])

        try:
            for command in commands:
                self._run(command, check=False)
            return FirewallOperationResult(True, self.name, "unquarantine", ip, "UFW quarantine rule removal requested", commands)
        except Exception as exc:
            logger.error(f"UFW unquarantine failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "unquarantine", ip, str(exc), commands)

    def unblock_ip(self, ip: str) -> FirewallOperationResult:
        if not self.is_available():
            return FirewallOperationResult(False, self.name, "unblock", ip, "ufw is not available")
        if not is_running_as_admin():
            return FirewallOperationResult(False, self.name, "unblock", ip, "Root privileges required")

        commands = [["ufw", "--force", "delete", "deny", "from", ip]]
        try:
            self._run(commands[0], check=False)
            return FirewallOperationResult(True, self.name, "unblock", ip, "UFW deny rule removal requested", commands)
        except Exception as exc:
            logger.error(f"UFW unblock failed for {ip}: {exc}")
            return FirewallOperationResult(False, self.name, "unblock", ip, str(exc), commands)

    def get_blocked_ips(self) -> List[str]:
        if not self.is_available():
            return []
        try:
            result = self._run(["ufw", "status"], check=False)
            blocked = []
            for line in result.stdout.splitlines():
                if "DENY" not in line.upper():
                    continue
                parts = line.split()
                if "from" in parts:
                    blocked.append(parts[-1])
            return sorted(set(blocked))
        except Exception as exc:
            logger.error(f"Failed to enumerate UFW rules: {exc}")
            return []


class NullFirewallAdapter(FirewallAdapter):
    name = "null_firewall"

    def supports_platform(self) -> bool:
        return True

    def is_available(self) -> bool:
        return True

    def block_ip(self, ip: str) -> FirewallOperationResult:
        return FirewallOperationResult(False, self.name, "block", ip, "No supported firewall adapter is available")

    def unblock_ip(self, ip: str) -> FirewallOperationResult:
        return FirewallOperationResult(False, self.name, "unblock", ip, "No supported firewall adapter is available")


def get_default_firewall_adapter() -> FirewallAdapter:
    candidates: List[FirewallAdapter] = [
        WindowsFirewallAdapter(),
        LinuxNftablesAdapter(),
        LinuxUfwAdapter(),
        LinuxIptablesAdapter(),
    ]
    for adapter in candidates:
        if adapter.supports_platform() and adapter.is_available():
            return adapter
    for adapter in candidates:
        if adapter.supports_platform():
            return adapter
    return NullFirewallAdapter()


def get_firewall_adapter_catalog() -> List[Dict[str, object]]:
    adapters: List[FirewallAdapter] = [
        WindowsFirewallAdapter(),
        LinuxNftablesAdapter(),
        LinuxUfwAdapter(),
        LinuxIptablesAdapter(),
    ]
    return [adapter.diagnostics() for adapter in adapters if adapter.supports_platform()]
