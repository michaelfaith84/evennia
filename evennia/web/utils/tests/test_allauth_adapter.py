"""Tests for Evennia's allauth MFA system check."""

from django.test import TestCase, override_settings


class TestEvenniaMfaCheck(TestCase):
    """Unit tests for evennia_mfa_settings_check."""

    def _run_check(self):
        from evennia.web.utils.allauth_checks import evennia_mfa_settings_check

        return evennia_mfa_settings_check(app_configs=None)

    @override_settings(
        MFA_PASSKEY_SIGNUP_ENABLED=False,
        MFA_SUPPORTED_TYPES=["totp", "recovery_codes", "webauthn"],
        ACCOUNT_EMAIL_VERIFICATION="none",
    )
    def test_disabled_no_errors(self):
        """When passkey signup is off, no errors regardless of other settings."""
        errors = self._run_check()
        self.assertEqual(errors, [])

    @override_settings(
        MFA_PASSKEY_SIGNUP_ENABLED=True,
        MFA_SUPPORTED_TYPES=["totp", "recovery_codes", "webauthn"],
        ACCOUNT_EMAIL_VERIFICATION="none",
    )
    def test_enabled_email_none_no_errors(self):
        """Passkey signup + EMAIL_VERIFICATION=none → no errors (Evennia's normal config)."""
        errors = self._run_check()
        self.assertEqual(errors, [])

    @override_settings(
        MFA_PASSKEY_SIGNUP_ENABLED=True,
        MFA_SUPPORTED_TYPES=["totp", "recovery_codes"],  # webauthn missing
        ACCOUNT_EMAIL_VERIFICATION="none",
    )
    def test_enabled_missing_webauthn_critical(self):
        """Passkey signup without webauthn in supported types → Critical regardless of email."""
        errors = self._run_check()
        self.assertEqual(len(errors), 1)
        self.assertIn("webauthn", errors[0].msg)

    @override_settings(
        MFA_PASSKEY_SIGNUP_ENABLED=True,
        MFA_SUPPORTED_TYPES=["totp", "recovery_codes", "webauthn"],
        ACCOUNT_EMAIL_VERIFICATION="optional",
        ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED=False,
        ACCOUNT_SIGNUP_FIELDS=["username*", "password1*", "password2*"],
    )
    def test_enabled_email_optional_errors(self):
        """Passkey signup + email not 'none' and misconfigured → email criticals fire."""
        errors = self._run_check()
        msgs = [e.msg for e in errors]
        self.assertTrue(any("EMAIL_VERIFICATION_BY_CODE_ENABLED" in m for m in msgs))
        self.assertTrue(any("email*" in m for m in msgs))
        self.assertTrue(any("mandatory" in m for m in msgs))
