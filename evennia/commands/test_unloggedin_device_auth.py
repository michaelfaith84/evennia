"""Tests for the device-auth branch of CmdUnconnectedConnect."""
from unittest.mock import MagicMock, patch

from django.test import override_settings

from evennia.utils.test_resources import BaseEvenniaTest


@override_settings(
    DEVICE_AUTH_TIMEOUT=300,
    MFA_SUPPORTED_TYPES=["totp", "recovery_codes", "webauthn"],
)
class TestConnectDeviceAuth(BaseEvenniaTest):
    """Tests for connect command's device-auth branch."""

    def setUp(self):
        super().setUp()
        from unittest.mock import MagicMock

        # Make self.account have no usable password (passwordless account)
        self.account.set_unusable_password()
        self.account.save()
        # Mock session.msg so we can inspect calls
        self.session.msg = MagicMock()

    def _run_connect(self, args):
        """Helper to run CmdUnconnectedConnect with given args on a mock session."""
        from evennia.commands.default.unloggedin import CmdUnconnectedConnect

        cmd = CmdUnconnectedConnect()
        cmd.caller = self.session
        cmd.session = self.session
        cmd.args = args
        cmd.func()

    @patch("evennia.server.pending_auth._has_passwordless_methods", return_value=True)
    @patch("twisted.internet.reactor.callLater")
    def test_passwordless_account_starts_device_auth(self, mock_callLater, mock_has_pw):
        """
        connect <username> (no password) on a passwordless account creates a
        PendingAuthScript and stores its key on session.ndb.
        """
        from evennia.scripts.models import ScriptDB

        self._run_connect(f" {self.account.username}")

        # A PendingAuthScript should have been created
        scripts = ScriptDB.objects.filter(db_key__startswith="pending_auth_")
        self.assertEqual(scripts.count(), 1)

        # Session should have the pending script key stored
        self.assertIsNotNone(self.session.ndb._pending_auth_script_key)

        # callLater should have been scheduled
        mock_callLater.assert_called_once()

        # Output should contain a URL
        sent = self.session.msg.call_args_list
        output = " ".join(str(c) for c in sent)
        self.assertIn("/auth/device/", output)

        # Cleanup
        scripts.delete()

    @patch("evennia.server.pending_auth._has_passwordless_methods", return_value=False)
    def test_no_passwordless_methods_shows_usage(self, mock_has_pw):
        """
        connect <username> (no password) on a password-only account shows usage message.
        """
        self._run_connect(f" {self.account.username}")

        sent = " ".join(str(c) for c in self.session.msg.call_args_list)
        self.assertIn("connect", sent.lower())
        self.assertNotIn("/auth/device/", sent)

    def test_unknown_username_shows_generic_error(self):
        """connect <nonexistent> (no password) shows generic auth failure."""
        self._run_connect(" doesnotexist_xyz")

        sent = " ".join(str(c) for c in self.session.msg.call_args_list)
        self.assertIn("incorrect", sent.lower())
        self.assertNotIn("/auth/device/", sent)


class TestCmdUnconnectedDeviceAuth(BaseEvenniaTest):
    """Tests for the auth cancel command."""

    def setUp(self):
        super().setUp()
        from unittest.mock import MagicMock

        self.session.msg = MagicMock()

    def test_cancel_with_pending_script(self):
        """auth cancel deletes the pending script and clears session state."""
        import time

        from evennia.commands.default.unloggedin import CmdUnconnectedDeviceAuth
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        script = create_script(PendingAuthScript, key="pending_auth_testcancel", persistent=False)
        script.db.token = "testcancel"
        script.db.username = self.account.username
        script.db.expires_at = time.time() + 300
        script.db.completed = False
        script.db.account_id = None

        self.session.ndb._pending_auth_script_key = "pending_auth_testcancel"

        cmd = CmdUnconnectedDeviceAuth()
        cmd.caller = self.session
        cmd.session = self.session
        cmd.args = " cancel"
        cmd.func()

        from evennia.scripts.models import ScriptDB

        self.assertFalse(ScriptDB.objects.filter(db_key="pending_auth_testcancel").exists())
        self.assertIsNone(self.session.ndb._pending_auth_script_key)

    def test_cancel_without_pending_script(self):
        """auth cancel with no pending session shows appropriate message."""
        from evennia.commands.default.unloggedin import CmdUnconnectedDeviceAuth

        self.session.ndb._pending_auth_script_key = None
        cmd = CmdUnconnectedDeviceAuth()
        cmd.caller = self.session
        cmd.session = self.session
        cmd.args = " cancel"
        cmd.func()

        sent = " ".join(str(c) for c in self.session.msg.call_args_list)
        self.assertIn("no pending", sent.lower())
