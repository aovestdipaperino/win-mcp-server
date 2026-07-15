"""Tests for Keychain credential lookup."""

from unittest.mock import patch

from win_mcp_server import credentials


# A realistic `security dump-keychain` fragment holding two win-mcp entries
# (in the order attributes appear: acct before svce) plus an unrelated item.
DUMP_KEYCHAIN_OUTPUT = '''\
keychain: "/Users/x/Library/Keychains/login.keychain-db"
attributes:
    0x00000007 <blob>="Some Website"
    "acct"<blob>="someone@example.com"
    "svce"<blob>="other-service"
attributes:
    0x00000007 <blob>="win-mcp"
    "acct"<blob>="supervisore@macnil.it"
    "svce"<blob>="win-mcp"
attributes:
    0x00000007 <blob>="win-mcp"
    "acct"<blob>="enzo@211.55.7"
    "svce"<blob>="win-mcp"
'''


class _FakeCompleted:
    def __init__(self, stdout):
        self.stdout = stdout
        self.returncode = 0


def test_list_accounts_enumerates_all_win_mcp_entries():
    """dump-keychain parsing returns every account for the service, not one."""
    with patch("win_mcp_server.credentials.subprocess.run",
               return_value=_FakeCompleted(DUMP_KEYCHAIN_OUTPUT)):
        accounts = credentials.keychain_list_accounts("win-mcp")

    assert accounts == ["supervisore@macnil.it", "enzo@211.55.7"]


def test_list_accounts_ignores_other_services():
    """Accounts belonging to a different service are not returned."""
    with patch("win_mcp_server.credentials.subprocess.run",
               return_value=_FakeCompleted(DUMP_KEYCHAIN_OUTPUT)):
        accounts = credentials.keychain_list_accounts("win-mcp")

    assert "someone@example.com" not in accounts


def test_get_credentials_picks_correct_account_with_multiple_entries():
    """Regression for #3: the right domain's credentials are returned even
    when several win-mcp entries exist (previously only the default was seen)."""
    stored = {
        "supervisore@macnil.it": "macnil-pass",
        "enzo@211.55.7": "vm-pass",
    }

    with patch.object(credentials, "keychain_list_accounts",
                       return_value=list(stored)), \
         patch.object(credentials, "keychain_check_expired", return_value=False), \
         patch.object(credentials, "keychain_get_password",
                      side_effect=lambda svc, acct: stored.get(acct)):
        # Parallels VM reached by IP -> domain 211.55.7
        username, password = credentials.get_credentials("10.211.55.7")

    assert (username, password) == ("enzo", "vm-pass")


def test_get_credentials_reads_env_variables():
    """Env vars WINRM-USER/WINRM-PWD short-circuit keychain and GUI prompt."""
    with patch.dict("os.environ",
                    {"WINRM-USER": "envuser", "WINRM-PWD": "envpass"},
                    clear=False), \
         patch.object(credentials, "keychain_list_accounts") as list_accounts, \
         patch.object(credentials, "prompt_credentials_gui") as prompt:
        username, password = credentials.get_credentials("10.211.55.7")

    assert (username, password) == ("envuser", "envpass")
    list_accounts.assert_not_called()
    prompt.assert_not_called()


def test_get_credentials_reads_underscore_env_variables():
    """Underscore variants WINRM_USER/WINRM_PWD are also honoured."""
    with patch.dict("os.environ",
                    {"WINRM_USER": "envuser", "WINRM_PWD": "envpass"},
                    clear=False), \
         patch.object(credentials, "keychain_list_accounts") as list_accounts, \
         patch.object(credentials, "prompt_credentials_gui") as prompt:
        username, password = credentials.get_credentials("10.211.55.7")

    assert (username, password) == ("envuser", "envpass")
    list_accounts.assert_not_called()
    prompt.assert_not_called()


def test_get_credentials_skips_expired_entries():
    """Expired cached entries are ignored so they get re-prompted (TTL on read)."""
    with patch.object(credentials, "keychain_list_accounts",
                      return_value=["enzo@211.55.7"]), \
         patch.object(credentials, "keychain_check_expired", return_value=True), \
         patch.object(credentials, "keychain_get_password", return_value="vm-pass"), \
         patch.object(credentials, "prompt_credentials_gui",
                      return_value=("prompted", "new-pass")) as prompt, \
         patch.object(credentials, "keychain_set_password"):
        username, password = credentials.get_credentials("10.211.55.7")

    prompt.assert_called_once()
    assert (username, password) == ("prompted", "new-pass")
