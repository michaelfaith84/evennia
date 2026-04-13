"""Tests for PendingAuthScript and related helpers."""
import time

from evennia.utils.test_resources import BaseEvenniaTest


class TestPendingAuthScript(BaseEvenniaTest):
    """Tests for PendingAuthScript."""

    def _make_script(self, username="testuser", timeout=300):
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        script = create_script(
            PendingAuthScript,
            key=f"pending_auth_test_{username}",
            persistent=False,
        )
        script.db.token = "abcd1234"
        script.db.username = username
        script.db.expires_at = time.time() + timeout
        script.db.completed = False
        script.db.account_id = None
        return script

    def test_token_format(self):
        """PendingAuthScript.generate_token() produces an 8-char hex token."""
        from evennia.server.pending_auth import PendingAuthScript

        token = PendingAuthScript.generate_token()
        self.assertEqual(len(token), 8)
        int(token, 16)  # raises ValueError if not valid hex

    def test_is_expired_false_when_fresh(self):
        """is_expired() returns False for a newly-created script."""
        script = self._make_script(timeout=300)
        self.assertFalse(script.is_expired())
        script.delete()

    def test_is_expired_true_when_past(self):
        """is_expired() returns True when expires_at is in the past."""
        script = self._make_script(timeout=-1)
        self.assertTrue(script.is_expired())
        script.delete()

    def test_complete_sets_fields(self):
        """complete(account) sets completed=True and account_id."""
        script = self._make_script()
        account = self.account  # provided by BaseEvenniaTestCase
        script.complete(account)
        self.assertTrue(script.db.completed)
        self.assertEqual(script.db.account_id, account.pk)
        script.delete()


class TestHasPasswordlessMethods(BaseEvenniaTest):
    """Tests for _has_passwordless_methods()."""

    def test_returns_false_for_password_account(self):
        """Account with only a usable password has no passwordless methods."""
        from evennia.server.pending_auth import _has_passwordless_methods

        # self.account is created with a password by BaseEvenniaTestCase
        self.assertFalse(_has_passwordless_methods(self.account))
