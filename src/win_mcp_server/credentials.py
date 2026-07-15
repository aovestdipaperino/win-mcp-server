#!/usr/bin/env python3
"""Secure credential management for WinRM connections."""

import getpass
import os
import subprocess
import sys
import time
from typing import Optional, Tuple


def get_domain_from_hostname(hostname: str) -> str:
    """Extract domain from FQDN or use fallback."""
    parts = hostname.split(".")
    if len(parts) > 1:
        # Extract domain from FQDN (e.g., server.domain.local -> domain.local)
        domain = ".".join(parts[1:])
        return domain

    # Fallback: use hostname.local
    return f"{hostname}.local"


def get_username_suggestion() -> str:
    """Get suggested username (current user)."""
    return getpass.getuser()


def keychain_list_accounts(service: str) -> list:
    """List all Keychain account names for a service.

    ``security find-generic-password -s <service>`` only ever returns a single
    (default) item, so it cannot be used to enumerate multiple stored accounts.
    ``dump-keychain`` lists every item, letting us find credentials for any
    host/domain regardless of how many entries exist.
    """
    accounts = []
    try:
        result = subprocess.run(
            ["security", "dump-keychain"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return accounts

    pending_account = None
    for line in result.stdout.split("\n"):
        stripped = line.strip()
        if stripped.startswith('"acct"<blob>='):
            # Extract the quoted account value
            parts = line.split('"')
            pending_account = parts[3] if len(parts) >= 4 else None
        elif stripped.startswith('"svce"<blob>=') and pending_account is not None:
            if f'"{service}"' in stripped:
                accounts.append(pending_account.replace("\\134", "\\"))
            pending_account = None
    return accounts


def keychain_get_password(service: str, account: str) -> Optional[str]:
    """Get password from macOS Keychain."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def keychain_set_password(
    service: str, account: str, password: str, ttl_hours: int = 4
):
    """Store password in macOS Keychain with TTL."""
    # Delete existing entry if present
    subprocess.run(
        ["security", "delete-generic-password", "-s", service, "-a", account],
        capture_output=True,
        check=False,
    )

    # Add new entry with comment containing expiration time
    expiry_time = int(time.time()) + (ttl_hours * 3600)

    subprocess.run(
        [
            "security",
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            password,
            "-j",
            f"expires:{expiry_time}",
        ],
        check=True,
    )


def keychain_check_expired(service: str, account: str) -> bool:
    """Check if keychain entry is expired."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-j"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse comment for expiry time
        comment = result.stdout.strip()
        if comment.startswith("expires:"):
            expiry_time = int(comment.split(":")[1])
            return time.time() > expiry_time
    except (subprocess.CalledProcessError, ValueError, IndexError):
        pass

    return True  # Assume expired if we can't determine


def prompt_credentials_gui(domain: str, suggested_username: str) -> Tuple[str, str]:
    """Prompt for credentials using macOS GUI dialogs."""
    # Use username@domain format for cleaner display
    suggested_account = f"{suggested_username}@{domain}"
    username_script = f'''
    display dialog "Enter username@domain for WinRM authentication:" ¬
    with title "WinRM Authentication" ¬
    with icon note ¬
    default answer "{suggested_account}" ¬
    buttons {{"Cancel", "OK"}} ¬
    default button "OK"
    '''

    try:
        result = subprocess.run(['osascript', '-e', username_script],
                              capture_output=True, text=True, check=True)
        account_input = result.stdout.strip().split('text returned:')[1].strip()

        # Parse both username@domain and domain\username formats
        if '@' in account_input:
            username, domain = account_input.split('@', 1)
        elif '\\' in account_input:
            domain, username = account_input.split('\\', 1)
        else:
            # If no domain specified, use original domain
            username = account_input

    except (subprocess.CalledProcessError, IndexError) as exc:
        raise RuntimeError("Username input cancelled") from exc

    # Prompt for password (hidden) - always show domain\username format in password prompt
    password_script = f'''
    display dialog "Enter password for {domain}\\\\{username}:" ¬
    with title "WinRM Authentication" ¬
    with icon note ¬
    default answer "" ¬
    with hidden answer ¬
    buttons {{"Cancel", "OK"}} ¬
    default button "OK"
    '''

    try:
        result = subprocess.run(['osascript', '-e', password_script],
                              capture_output=True, text=True, check=True)
        password = result.stdout.strip().split('text returned:')[1].strip()
    except (subprocess.CalledProcessError, IndexError) as exc:
        raise RuntimeError("Password input cancelled") from exc

    if not password:
        raise RuntimeError("Password cannot be empty")

    return username, password


def get_credentials(hostname: str) -> Tuple[str, str]:
    """Get credentials for hostname with GUI prompting and caching."""
    domain = get_domain_from_hostname(hostname)
    service = "win-mcp"

    # Environment variables take precedence over cached/prompted credentials.
    # This allows non-interactive/CI usage without any GUI prompt.
    env_user = os.environ.get("WINRM-USER") or os.environ.get("WINRM_USER")
    env_pwd = os.environ.get("WINRM-PWD") or os.environ.get("WINRM_PWD")
    if env_user and env_pwd:
        return env_user, env_pwd

    # Check for cached credentials across all stored accounts for this
    # service. We enumerate every account (find-generic-password only returns
    # one) and match those belonging to this domain, in both the
    # username@domain and domain\username formats.
    for account in keychain_list_accounts(service):
        # Determine the username for this account if it matches the domain
        username = None
        if '@' in account and account.endswith(f'@{domain}'):
            username = account.split('@')[0]
        elif '\\' in account and account.startswith(f'{domain}\\'):
            username = account.split('\\')[1]

        if not username:
            continue

        # Honour the TTL: skip expired entries so they get re-prompted
        if keychain_check_expired(service, account):
            continue

        password = keychain_get_password(service, account)
        if password:
            return username, password

    # No cached credentials found, prompt using GUI
    username, password = prompt_credentials_gui(domain, get_username_suggestion())

    # Store in keychain using @ format
    account = f"{username}@{domain}"
    try:
        keychain_set_password(service, account, password)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not cache credentials: {e}", file=sys.stderr)

    return username, password


def clear_cached_credentials(hostname: str) -> bool:
    """Clear cached credentials for hostname."""
    domain = get_domain_from_hostname(hostname)
    service = "win-mcp"
    cleared = False

    try:
        # Get account info (same logic as get_credentials)
        result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service
        ], capture_output=True, text=True, check=False)

        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'acct' in line and domain in line:
                    # Extract account name - it's at index 3
                    parts = line.split('"')
                    if len(parts) >= 4:
                        account = parts[3]  # Account is at index 3
                        # Handle both formats: username@domain or domain\username
                        if (('@' in account and domain in account) or
                                ('\\' in account and domain in account)):
                            try:
                                subprocess.run([
                                    'security', 'delete-generic-password',
                                    '-s', service,
                                    '-a', account
                                ], capture_output=True, check=True)
                                cleared = True
                            except subprocess.CalledProcessError:
                                pass
    except subprocess.CalledProcessError:
        pass

    return cleared


def test_credentials_available(hostname: str) -> bool:
    """Test if valid credentials are available for hostname."""
    domain = get_domain_from_hostname(hostname)
    service = "win-mcp"

    try:
        result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service,
            '-g'
        ], capture_output=True, text=True, check=False)

        if result.returncode == 0:
            for line in result.stderr.split('\n'):
                if 'acct' in line and domain in line:
                    # Handle both @ and \ formats
                    if f'@{domain}' in line or f'{domain}\\' in line:
                        parts = line.split('"')
                        if len(parts) >= 2:
                            account_match = parts[1]
                            if not keychain_check_expired(service, account_match):
                                return True
    except subprocess.CalledProcessError:
        pass

    return False
