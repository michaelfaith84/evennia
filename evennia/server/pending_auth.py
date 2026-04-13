"""
PendingAuthScript — short-lived DB record for telnet device-auth (QR code login).

A ``PendingAuthScript`` is created when a telnet player types ``connect username``
with no password and their account has passwordless login methods (OAuth or passkey).
The script holds a token that ties a telnet session to a web-based auth flow.

The script is ``persistent=False``: tokens live at most ``DEVICE_AUTH_TIMEOUT``
seconds and do not need to survive server restarts.
"""

import secrets
import time

from evennia.scripts.scripts import DefaultScript


class PendingAuthScript(DefaultScript):
    """
    Tracks a pending device-auth token for a single telnet login attempt.

    Attributes stored in ``script.db``:
        token (str): 8-character hex token used in the QR URL.
        username (str): account username this token is for.
        expires_at (float): ``time.time()`` value after which the token is invalid.
        completed (bool): set to ``True`` by the web callback on success.
        account_id (int or None): account pk, set on completion.
    """

    @staticmethod
    def generate_token():
        """
        Generate a URL-safe 8-character hex token.

        Returns:
            str: 8-character lowercase hex string.
        """
        return secrets.token_hex(4)

    def is_expired(self):
        """
        Check whether this token has expired.

        Returns:
            bool: ``True`` if the current time is past ``expires_at``.
        """
        return time.time() > self.db.expires_at

    def complete(self, account):
        """
        Mark this token as successfully completed.

        Args:
            account: The Evennia ``AccountDB`` instance that authenticated.
        """
        self.db.completed = True
        self.db.account_id = account.pk


def _has_passwordless_methods(account):
    """
    Return ``True`` if the account has at least one passwordless login method.

    Passwordless methods are OAuth social accounts or WebAuthn passkey
    authenticators. Accounts with only a usable password return ``False``.

    Args:
        account: An Evennia ``AccountDB`` instance.

    Returns:
        bool
    """
    try:
        from allauth.mfa.models import Authenticator
        from allauth.socialaccount.models import SocialAccount

        has_passkey = Authenticator.objects.filter(
            user=account, type=Authenticator.Type.WEBAUTHN
        ).exists()
        has_oauth = SocialAccount.objects.filter(user=account).exists()
        return has_passkey or has_oauth
    except Exception:
        return False


def get_pending_script(token):
    """
    Look up a ``PendingAuthScript`` by token.

    Args:
        token (str): the 8-character hex token from the QR URL.

    Returns:
        PendingAuthScript or None: the script if found, else ``None``.
    """
    from evennia.scripts.models import ScriptDB

    return ScriptDB.objects.filter(db_key=f"pending_auth_{token}").first()
