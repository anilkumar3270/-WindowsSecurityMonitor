"""
firewall_demo.py
Module 6: Defensive Firewall Demonstration & SOAR Dynamic Isolation Simulator.
- Safely executes read-only queries against Windows Defender Firewall.
- Generates simulated, copy-pasteable PowerShell and netsh blocking rules for detected attacker IPs.
- Educates on Preventive vs. Detective vs. Corrective cybersecurity controls.
"""

import subprocess
import shutil
from typing import Dict, Any, List

def query_windows_firewall_status() -> Dict[str, Any]:
    """
    Executes a read-only query to inspect Windows Defender Firewall profile states.
    Safe and non-destructive.
    """
    netsh_path = shutil.which("netsh")
    if not netsh_path:
        return {
            "status": "unavailable",
            "raw_output": "netsh utility not found in PATH.",
            "profiles": {}
        }

    try:
        cmd = ["netsh", "advfirewall", "show", "allprofiles", "state"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        raw = res.stdout.strip()
        profiles = {}

        current_profile = None
        for line in raw.splitlines():
            line_str = line.strip()
            if "Profile Settings:" in line_str:
                current_profile = line_str.split("Profile")[0].strip()
            elif "State" in line_str and current_profile:
                state_val = line_str.split()[-1]
                profiles[current_profile] = state_val

        return {
            "status": "success",
            "raw_output": raw,
            "profiles": profiles
        }
    except Exception as e:
        return {
            "status": "error",
            "raw_output": f"Error querying firewall: {str(e)}",
            "profiles": {}
        }

def generate_remediation_commands(target_ip: str, rule_suffix: str = "BCS703_ISOLATION") -> Dict[str, str]:
    """
    Generates simulated host firewall isolation rules (PowerShell and Netsh)
    along with their exact reversal commands.
    """
    rule_name = f"Block_{target_ip}_{rule_suffix}"

    ps_block = (
        f"New-NetFirewallRule -DisplayName '{rule_name}' "
        f"-Direction Inbound -Action Block -RemoteAddress '{target_ip}' "
        f"-Description 'Automated threat containment triggered by BCS703 Security Monitor'"
    )
    ps_unblock = f"Remove-NetFirewallRule -DisplayName '{rule_name}'"

    netsh_block = (
        f'netsh advfirewall firewall add rule name="{rule_name}" '
        f'dir=in action=block remoteip={target_ip} enable=yes'
    )
    netsh_unblock = f'netsh advfirewall firewall delete rule name="{rule_name}"'

    return {
        "target_ip": target_ip,
        "rule_name": rule_name,
        "powershell_block": ps_block,
        "powershell_unblock": ps_unblock,
        "netsh_block": netsh_block,
        "netsh_unblock": netsh_unblock,
        "safety_note": "Simulated SOAR corrective action. Reversible command generated without executing host modification."
    }
