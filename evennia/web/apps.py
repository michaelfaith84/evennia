"""
AppConfig for evennia.web.

Performs startup tasks that must run after all apps are ready, such as
replacing allauth's MFA system check with an Evennia-aware version.
"""

from django.apps import AppConfig


class EvenniaWebConfig(AppConfig):
    """
    Django AppConfig for the evennia.web package.

    Overrides allauth's MFA system check with an Evennia-aware version
    that does not require mandatory email verification when
    ``ACCOUNT_EMAIL_VERIFICATION = "none"``.
    """

    name = "evennia.web"
    default = True  # auto-selected when "evennia.web" is in INSTALLED_APPS

    def ready(self):
        from allauth.mfa.checks import settings_check as _allauth_mfa_check
        from django.core.checks import registry as checks_module

        from evennia.web.utils.allauth_checks import evennia_mfa_settings_check

        # Remove allauth's check from the registry sets.
        checks_module.registry.registered_checks.discard(_allauth_mfa_check)
        checks_module.registry.deployment_checks.discard(_allauth_mfa_check)

        # Register Evennia's replacement.
        checks_module.register(evennia_mfa_settings_check)
