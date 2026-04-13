"""
Evennia-aware replacement for allauth's MFA system check.

Replaces ``allauth.mfa.checks.settings_check`` (registered via
``allauth.mfa.apps.MFAConfig.ready()``).  The original check fires Critical
errors when ``MFA_PASSKEY_SIGNUP_ENABLED = True`` that require mandatory email
verification.  Those checks protect against session loss during email
verification -- but Evennia uses ``ACCOUNT_EMAIL_VERIFICATION = "none"``,
meaning there is no verification step and no session to lose.  We skip the
three email-related criticals in that case.

The one critical that always fires remains: webauthn must be in
``MFA_SUPPORTED_TYPES``.
"""

from django.core.checks import Critical, register


@register()
def evennia_mfa_settings_check(app_configs, **kwargs):
    """
    Evennia-aware MFA settings check.

    Replaces allauth's built-in check which unconditionally requires
    email verification when ``MFA_PASSKEY_SIGNUP_ENABLED = True``.
    Evennia skips those requirements when ``ACCOUNT_EMAIL_VERIFICATION
    = "none"`` because no verification step is performed and no session
    state can be lost.

    Args:
        app_configs: Passed by Django's check framework (unused).
        **kwargs: Additional keyword arguments from Django's check framework.

    Returns:
        list: A list of :class:`django.core.checks.Critical` instances
        describing any configuration errors, or an empty list if the
        configuration is valid.

    """
    from django.conf import settings as django_settings

    from allauth.account import app_settings as account_settings
    from allauth.mfa import app_settings
    from allauth.mfa.models import Authenticator

    ret = []

    # Read MFA_PASSKEY_SIGNUP_ENABLED directly from Django settings because
    # allauth's app_settings.PASSKEY_SIGNUP_ENABLED short-circuits to False when
    # webauthn is missing from SUPPORTED_TYPES, hiding the misconfiguration.
    passkey_signup_requested = getattr(django_settings, "MFA_PASSKEY_SIGNUP_ENABLED", False)
    if not passkey_signup_requested:
        return ret

    # This critical always applies: passkey signup needs the webauthn authenticator.
    if Authenticator.Type.WEBAUTHN not in app_settings.SUPPORTED_TYPES:
        ret.append(
            Critical(
                msg="MFA_PASSKEY_SIGNUP_ENABLED requires MFA_SUPPORTED_TYPES to include 'webauthn'"
            )
        )
        # Without webauthn, the remaining checks are irrelevant.
        return ret

    # The following three criticals only apply when email verification is active.
    # With ACCOUNT_EMAIL_VERIFICATION = "none", there is no verification step,
    # so passkey_signup session state is never lost and the checks are irrelevant.
    email_verification = account_settings.EMAIL_VERIFICATION
    if email_verification != account_settings.EmailVerificationMethod.NONE:
        if not account_settings.EMAIL_VERIFICATION_BY_CODE_ENABLED:
            ret.append(
                Critical(
                    msg="MFA_PASSKEY_SIGNUP_ENABLED requires ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED"
                )
            )
        email_required = account_settings.SIGNUP_FIELDS.get("email", {}).get("required")
        if not email_required:
            ret.append(
                Critical(
                    msg="MFA_PASSKEY_SIGNUP_ENABLED requires ACCOUNT_SIGNUP_FIELDS to contain 'email*'"
                )
            )
        if email_verification != account_settings.EmailVerificationMethod.MANDATORY:
            ret.append(
                Critical(
                    msg="MFA_PASSKEY_SIGNUP_ENABLED requires ACCOUNT_EMAIL_VERIFICATION = 'mandatory'"
                )
            )

    return ret
