"""
Utilities for MFA (multi-factor authentication) validation on non-web paths
such as the telnet/SSH login flow and GMCP Char.Login.

These wrap allauth's internal TOTP and RecoveryCodes machinery so that
Evennia's unloggedin commands and inputfuncs don't need to import allauth
internals directly.
"""

from django.db import ProgrammingError


def get_mfa_authenticator(account, auth_type):
    """
    Return the allauth Authenticator instance for the given account and type,
    or None if not set up.

    Args:
        account: an Evennia AccountDB instance.
        auth_type (str): one of ``"totp"`` or ``"recovery_codes"``.

    Returns:
        allauth.mfa.models.Authenticator or None
    """
    try:
        from allauth.mfa.models import Authenticator

        return Authenticator.objects.filter(
            user=account, type=auth_type
        ).first()
    except (ImportError, ProgrammingError):
        return None


def is_mfa_enabled(account):
    """
    Return True if the account has any MFA method active (TOTP or recovery codes).

    Args:
        account: an Evennia AccountDB instance.

    Returns:
        bool
    """
    return (
        get_mfa_authenticator(account, "totp") is not None
        or get_mfa_authenticator(account, "recovery_codes") is not None
    )


def validate_totp_code(account, code):
    """
    Validate a TOTP code for the given account.

    Args:
        account: an Evennia AccountDB instance.
        code (str): the 6-digit TOTP code entered by the user.

    Returns:
        bool: True if the code is valid and unused.
    """
    instance = get_mfa_authenticator(account, "totp")
    if not instance:
        return False
    try:
        from allauth.mfa.totp.internal.auth import TOTP

        return TOTP(instance).validate_code(code.strip())
    except (ImportError, Exception):
        return False


def validate_recovery_code(account, code):
    """
    Validate a one-time recovery code for the given account.

    Args:
        account: an Evennia AccountDB instance.
        code (str): the recovery code entered by the user.

    Returns:
        bool: True if the code is valid and unused (consuming it on success).
    """
    instance = get_mfa_authenticator(account, "recovery_codes")
    if not instance:
        return False
    try:
        from allauth.mfa.recovery_codes.internal.auth import RecoveryCodes

        return RecoveryCodes(instance).validate_code(code.strip())
    except (ImportError, Exception):
        return False


def validate_mfa_code(account, code):
    """
    Validate either a TOTP code or a recovery code for the given account.
    TOTP codes are 6 digits; recovery codes are longer.

    Args:
        account: an Evennia AccountDB instance.
        code (str): the code entered by the user.

    Returns:
        bool: True if the code is valid.
    """
    code = code.strip()
    if validate_totp_code(account, code):
        return True
    if validate_recovery_code(account, code):
        return True
    return False
