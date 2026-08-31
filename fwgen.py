#!/usr/bin/env python3
"""
fwgen.py - Simple interactive firewall rule manager (iptables / ip6tables).

Menu-driven tool to add / modify / delete firewall rules with validated input.
Every action previews the exact command and asks for confirmation before it runs.

For educational / authorized lab use only.
"""

import ipaddress
import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def require_root():
    """Exit unless we have root, since iptables needs it."""
    if os.geteuid() != 0:
        print("[!] This tool must be run as root. Try: sudo python3 fwgen.py")
        sys.exit(1)


def ip_family(value):
    """Return 4, 6, or None for an IP / CIDR string."""
    value = value.strip()
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return net.version
        addr = ipaddress.ip_address(value)
        return addr.version
    except ValueError:
        return None


def fw_binary(family):
    """Pick the right firewall binary for the address family."""
    return "ip6tables" if family == 6 else "iptables"


def ask_ip(prompt="Enter IP or CIDR: "):
    """Return (normalized_ip, family). Validated; IPv4 and IPv6 both supported."""
    while True:
        raw = input(prompt).strip()
        fam = ip_family(raw)
        if fam:
            return raw, fam
        print("    [!] Invalid IP. Examples: 192.168.1.50 , 10.0.0.0/24 , 2001:db8::1")


def ask_port(prompt="Enter port (1-65535): "):
    while True:
        raw = input(prompt).strip()
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            return int(raw)
        print("    [!] Invalid port. Must be a number between 1 and 65535.")


def ask_proto(prompt="Protocol [tcp/udp] (default tcp): "):
    raw = input(prompt).strip().lower()
    if raw == "udp":
        return "udp"
    if raw not in ("", "tcp"):
        print("    [!] Unknown protocol, defaulting to tcp.")
    return "tcp"


def run_rule(cmd, destructive=False):
    """Preview a command, confirm, then run it."""
    print("\n[>] Command to run:")
    print("    " + " ".join(cmd))
    if destructive:
        print("    [!] WARNING: this is a disruptive change.")
    if input("Apply this rule? [y/N]: ").strip().lower() != "y":
        print("[-] Skipped. Nothing was changed.\n")
        return False
    try:
        subprocess.run(cmd, check=True)
        print("[+] Rule applied.\n")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"[!] {cmd[0]} returned an error (exit {exc.returncode}).\n")
    except FileNotFoundError:
        print(f"[!] {cmd[0]} not found on this system.\n")
    return False


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def block_ip():
    ip, fam = ask_ip()
    fw = fw_binary(fam)
    # -I inserts at the TOP so the block takes precedence over any earlier ACCEPT.
    run_rule([fw, "-I", "INPUT", "-s", ip, "-j", "DROP"])


def allow_ip():
    ip, fam = ask_ip()
    fw = fw_binary(fam)
    run_rule([fw, "-I", "INPUT", "-s", ip, "-j", "ACCEPT"])


def isolate_host():
    """Quarantine the host: drop network traffic but keep the box usable
    (loopback + already-established connections survive, so you don't get
    locked out of an existing SSH session)."""
    print("\n[!] Isolation cuts the host off from the network.")
    print("    Loopback and established connections are kept so you are not")
    print("    locked out of your current session. New traffic is dropped.")
    admin = input("Optional admin IP to keep full access (blank to skip): ").strip()
    admin_fam = ip_family(admin) if admin else None
    if admin and not admin_fam:
        print("    [!] Invalid admin IP, skipping it.")
        admin = ""
    if input("Type ISOLATE to confirm: ").strip() != "ISOLATE":
        print("[-] Cancelled.\n")
        return

    fw = "iptables"  # policies below are set for IPv4; see note in README
    # Keep the host functional first, THEN drop everything else.
    run_rule([fw, "-I", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_rule([fw, "-I", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
    run_rule([fw, "-I", "INPUT", "-m", "conntrack",
              "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    run_rule([fw, "-I", "OUTPUT", "-m", "conntrack",
              "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
    if admin:
        afw = fw_binary(admin_fam)
        run_rule([afw, "-I", "INPUT", "-s", admin, "-j", "ACCEPT"])
        run_rule([afw, "-I", "OUTPUT", "-d", admin, "-j", "ACCEPT"])
    run_rule([fw, "-P", "INPUT", "DROP"], destructive=True)
    run_rule([fw, "-P", "OUTPUT", "DROP"], destructive=True)
    run_rule([fw, "-P", "FORWARD", "DROP"], destructive=True)


def open_port():
    proto = ask_proto()
    port = ask_port()
    run_rule(["iptables", "-A", "INPUT", "-p", proto,
              "--dport", str(port), "-j", "ACCEPT"])


def close_port():
    proto = ask_proto()
    port = ask_port()
    run_rule(["iptables", "-I", "INPUT", "-p", proto,
              "--dport", str(port), "-j", "DROP"])


def list_rules():
    fw = "iptables"
    if input("Show IPv6 rules instead? [y/N]: ").strip().lower() == "y":
        fw = "ip6tables"
    print(f"\n[>] Current INPUT rules ({fw}):\n")
    subprocess.run([fw, "-L", "INPUT", "-n", "--line-numbers"])
    print()


def delete_rule():
    fw = "iptables"
    if input("Delete from IPv6 rules? [y/N]: ").strip().lower() == "y":
        fw = "ip6tables"
    subprocess.run([fw, "-L", "INPUT", "-n", "--line-numbers"])
    chain = input("Chain [INPUT/OUTPUT/FORWARD] (default INPUT): ").strip().upper()
    if chain not in ("INPUT", "OUTPUT", "FORWARD"):
        chain = "INPUT"
    line = input("Line number to delete: ").strip()
    if not line.isdigit():
        print("    [!] Invalid line number.\n")
        return
    run_rule([fw, "-D", chain, line], destructive=True)


def reset_firewall():
    print("\n[!] Reset flushes ALL rules. Choose a mode:")
    print("    1) Safe   - default DROP, but keep loopback + established (recommended)")
    print("    2) Open   - default ACCEPT (allow everything; use only in a lab)")
    mode = input("Select mode [1/2]: ").strip()
    if mode not in ("1", "2"):
        print("[-] Cancelled.\n")
        return
    if input("Type RESET to confirm: ").strip() != "RESET":
        print("[-] Cancelled.\n")
        return

    fw = "iptables"
    run_rule([fw, "-F"], destructive=True)
    if mode == "1":
        run_rule([fw, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
        run_rule([fw, "-A", "INPUT", "-m", "conntrack",
                  "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        run_rule([fw, "-P", "INPUT", "DROP"], destructive=True)
        run_rule([fw, "-P", "FORWARD", "DROP"], destructive=True)
        run_rule([fw, "-P", "OUTPUT", "ACCEPT"])
    else:
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            run_rule([fw, "-P", chain, "ACCEPT"], destructive=True)


def save_rules():
    """Persist current rules so they survive a reboot."""
    print("\n[>] This writes current IPv4 rules to /etc/iptables/rules.v4")
    if input("Save now? [y/N]: ").strip().lower() != "y":
        print("[-] Skipped.\n")
        return
    try:
        os.makedirs("/etc/iptables", exist_ok=True)
        with open("/etc/iptables/rules.v4", "w") as fh:
            subprocess.run(["iptables-save"], stdout=fh, check=True)
        print("[+] Saved to /etc/iptables/rules.v4\n")
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
        print(f"[!] Could not save rules: {exc}\n")


# ---------------------------------------------------------------------------
# Menu
# ---------------------------------------------------------------------------

MENU = """
=== Firewall Rule Manager ===
1) Block an IP
2) Allow an IP
3) Isolate host (quarantine, keeps you logged in)
4) Open a port
5) Close a port
6) List current rules
7) Delete a rule
8) Reset firewall
9) Save rules (persist across reboot)
0) Exit
"""

ACTIONS = {
    "1": block_ip,
    "2": allow_ip,
    "3": isolate_host,
    "4": open_port,
    "5": close_port,
    "6": list_rules,
    "7": delete_rule,
    "8": reset_firewall,
    "9": save_rules,
}


def main():
    require_root()
    while True:
        print(MENU)
        choice = input("Select an option: ").strip()
        if choice == "0":
            print("Bye.")
            break
        action = ACTIONS.get(choice)
        if action:
            action()
        else:
            print("[!] Invalid option, try again.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted. Exiting.")
