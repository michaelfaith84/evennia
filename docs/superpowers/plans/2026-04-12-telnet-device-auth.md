# Telnet Device Auth (QR Code Passwordless Login) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow players who registered via OAuth or passkey (no usable password) to log in via the telnet client by scanning a QR code that redirects to a web-based auth flow.

**Architecture:** `connect username` (no password) triggers a `PendingAuthScript` DB record holding a short-lived token. The telnet session shows a QR code URL and polls the DB every 3 seconds via `reactor.callLater`. A companion Django view lets the player authenticate on their phone; on success it marks the script completed. The poller detects this and calls `session.sessionhandler.login()`.

**Tech Stack:** Python 3.12, Django 6, Twisted reactor, django-allauth, `qrcode` (already installed), Evennia `DefaultScript`, `reactor.callLater`.

**Spec:** `docs/superpowers/specs/2026-04-12-telnet-device-auth-design.md`

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Create | `evennia/server/pending_auth.py` | `PendingAuthScript` + `_has_passwordless_methods()` helper |
| Create | `evennia/server/tests/test_pending_auth.py` | Tests for `PendingAuthScript` |
| Modify | `evennia/commands/default/unloggedin.py` | Add device-auth branch to `CmdUnconnectedConnect`; add `CmdUnconnectedDeviceAuth`; add `_poll_device_auth()` |
| Create | `evennia/commands/tests/test_unloggedin_device_auth.py` | Tests for command-level device auth behaviour |
| Modify | `evennia/commands/default/cmdset_unloggedin.py` | Register `CmdUnconnectedDeviceAuth` |
| Modify | `evennia/web/website/views/accounts.py` | Add `device_auth` and `device_complete` views |
| Create | `evennia/web/templates/website/device_auth_complete.html` | "You're signed in — return to terminal" page |
| Create | `evennia/web/templates/website/device_auth_expired.html` | "This link has expired" page |
| Modify | `evennia/web/website/urls.py` | Add `/auth/device/<token>/` and `/auth/device/<token>/complete/` |
| Create | `evennia/web/utils/tests/test_device_auth_views.py` | Tests for `device_auth` and `device_complete` views |
| Modify | `evennia/settings_default.py` | Add `DEVICE_AUTH_TIMEOUT = 300` |

---

## Task 1: `PendingAuthScript` and passwordless detection helper

**Files:**
- Create: `evennia/server/pending_auth.py`
- Create: `evennia/server/tests/test_pending_auth.py`

`PendingAuthScript` is a `DefaultScript` subclass. It stores token, username, expiry, and
completion state in `script.db`. `persistent=False` so it doesn't survive restarts (5-minute
tokens don't need to). The key is `"pending_auth_<token>"` enabling direct lookup.

`_has_passwordless_methods(account)` checks if the account has OAuth social accounts or
WebAuthn authenticators — used by the connect command to decide whether to offer the QR flow.

- [ ] **Step 1: Write failing tests**

Create `evennia/server/tests/test_pending_auth.py`:

```python
"""Tests for PendingAuthScript and related helpers."""
import time

from django.test import TestCase, override_settings

from evennia.utils.test_resources import BaseEvenniaTestCase


class TestPendingAuthScript(BaseEvenniaTestCase):
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
        """PendingAuthScript.create_for() produces an 8-char hex token."""
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        script = create_script(PendingAuthScript, key="pending_auth_tok", persistent=False)
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


class TestHasPasswordlessMethods(BaseEvenniaTestCase):
    """Tests for _has_passwordless_methods()."""

    def test_returns_false_for_password_account(self):
        """Account with only a usable password has no passwordless methods."""
        from evennia.server.pending_auth import _has_passwordless_methods

        # self.account is created with a password by BaseEvenniaTestCase
        self.assertFalse(_has_passwordless_methods(self.account))
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
uv run pytest evennia/server/tests/test_pending_auth.py -v
```

Expected: `ImportError: cannot import name 'PendingAuthScript'`

- [ ] **Step 3: Implement `evennia/server/pending_auth.py`**

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
uv run pytest evennia/server/tests/test_pending_auth.py -v
```

Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add evennia/server/pending_auth.py evennia/server/tests/test_pending_auth.py
git commit -m "feat: add PendingAuthScript for telnet device-auth flow"
```

---

## Task 2: `DEVICE_AUTH_TIMEOUT` setting

**Files:**
- Modify: `evennia/settings_default.py` (after `MFA_PASSKEY_SIGNUP_ENABLED` block, around line 1041)

- [ ] **Step 1: Add the setting**

In `evennia/settings_default.py`, find the block ending with `MFA_PASSKEY_SIGNUP_ENABLED = True`
and add after it:

```python
# Timeout in seconds for telnet device-auth (QR code) sessions.
# After this time the QR code expires and the player must reconnect and try again.
DEVICE_AUTH_TIMEOUT = 300  # 5 minutes
```

- [ ] **Step 2: Commit**

```bash
git add evennia/settings_default.py
git commit -m "feat: add DEVICE_AUTH_TIMEOUT setting for telnet device-auth"
```

---

## Task 3: `_poll_device_auth` and connect command changes

**Files:**
- Modify: `evennia/commands/default/unloggedin.py`
- Create: `evennia/commands/tests/__init__.py` (if not exists)
- Create: `evennia/commands/tests/test_unloggedin_device_auth.py`

`CmdUnconnectedConnect.func()` gets a new branch: when `len(parts) == 1` (username only,
no password), look up the account, check `_has_passwordless_methods`, and either start the
device-auth flow or fall through to the existing usage message.

`_poll_device_auth(session, script_key)` is a module-level function called by
`reactor.callLater` — it must not be a method so Twisted can call it directly.

- [ ] **Step 1: Write failing tests**

```bash
touch evennia/commands/tests/__init__.py
```

Create `evennia/commands/tests/test_unloggedin_device_auth.py`:

```python
"""Tests for the device-auth branch of CmdUnconnectedConnect."""
from unittest.mock import MagicMock, patch

from django.test import override_settings

from evennia.utils.test_resources import BaseEvenniaTestCase


@override_settings(
    DEVICE_AUTH_TIMEOUT=300,
    MFA_SUPPORTED_TYPES=["totp", "recovery_codes", "webauthn"],
)
class TestConnectDeviceAuth(BaseEvenniaTestCase):
    """Tests for connect command's device-auth branch."""

    def setUp(self):
        super().setUp()
        # Make self.account have no usable password (passwordless account)
        self.account.set_unusable_password()
        self.account.save()

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
```

- [ ] **Step 2: Run to confirm failure**

```bash
uv run pytest evennia/commands/tests/test_unloggedin_device_auth.py -v
```

Expected: failures — the device-auth branch doesn't exist yet.

- [ ] **Step 3: Add `_poll_device_auth` to `unloggedin.py`**

Add this module-level function near the top of `unloggedin.py`, after the imports:

```python
def _poll_device_auth(session, script_key):
    """
    Poll a PendingAuthScript to check whether the player has authenticated on the web.

    Called by ``reactor.callLater`` every 3 seconds during a pending device-auth
    session. Reschedules itself until the token is completed, expired, or the
    session has disconnected.

    Args:
        session: The Evennia ``Session`` waiting for authentication.
        script_key (str): The ``db_key`` of the ``PendingAuthScript`` (e.g.
            ``"pending_auth_a3f9c2b1"``).
    """
    from evennia.scripts.models import ScriptDB

    # If the session is gone (disconnected), clean up and stop.
    if not session or not session.sessionhandler.session_from_sessid(session.sessid):
        script = ScriptDB.objects.filter(db_key=script_key).first()
        if script:
            script.delete()
        return

    script = ScriptDB.objects.filter(db_key=script_key).first()

    # Script was deleted externally (e.g. auth cancel command).
    if not script:
        return

    if script.is_expired():
        script.delete()
        session.ndb._pending_auth_script_key = None
        session.msg(
            "|RAuthentication timed out.|n\n"
            "Use |wconnect <username>|n to try again."
        )
        return

    if script.db.completed:
        from evennia.accounts.models import AccountDB

        account = AccountDB.objects.filter(pk=script.db.account_id).first()
        script.delete()
        session.ndb._pending_auth_script_key = None
        if account:
            session.msg("|gAuthenticated! Welcome, %s.|n" % account.name)
            session.sessionhandler.login(session, account)
        else:
            session.msg("|RAuthentication failed: account not found. Please try again.|n")
        return

    # Not done yet — reschedule.
    from twisted.internet import reactor
    reactor.callLater(3, _poll_device_auth, session, script_key)
```

- [ ] **Step 4: Modify `CmdUnconnectedConnect.func()` to add the device-auth branch**

In `CmdUnconnectedConnect.func()`, replace the block starting at `if len(parts) != 2:`:

```python
        if len(parts) == 1:
            # Username only — no password provided.
            # Check whether this account uses passwordless login.
            name = parts[0]
            from evennia.accounts.models import AccountDB
            from evennia.server.pending_auth import (
                PendingAuthScript,
                _has_passwordless_methods,
                get_pending_script,
            )
            from evennia.utils.create import create_script

            account = AccountDB.objects.get_account_from_name(name)
            if account and not account.has_usable_password() and _has_passwordless_methods(account):
                # Cancel any existing pending auth for this session.
                existing_key = session.ndb._pending_auth_script_key
                if existing_key:
                    old_script = get_pending_script(
                        existing_key.replace("pending_auth_", "")
                    )
                    if old_script:
                        old_script.delete()

                # Create the pending auth script.
                token = PendingAuthScript.generate_token()
                script_key = f"pending_auth_{token}"
                script = create_script(
                    PendingAuthScript,
                    key=script_key,
                    persistent=False,
                )
                script.db.token = token
                script.db.username = account.username
                import time as _time
                script.db.expires_at = _time.time() + settings.DEVICE_AUTH_TIMEOUT
                script.db.completed = False
                script.db.account_id = None

                session.ndb._pending_auth_script_key = script_key

                # Build the QR URL.
                hostname = getattr(settings, "SERVER_HOSTNAME", "localhost")
                webserver_ports = getattr(settings, "WEBSERVER_PORTS", [(4001, 4005)])
                port = webserver_ports[0][0] if webserver_ports else 4001
                scheme = "https" if port == 443 else "http"
                port_suffix = "" if port in (80, 443) else f":{port}"
                url = f"{scheme}://{hostname}{port_suffix}/auth/device/{token}/"

                # Render QR code as ASCII art.
                try:
                    import io
                    import qrcode
                    qr = qrcode.QRCode()
                    qr.add_data(url)
                    qr.make(fit=True)
                    buf = io.StringIO()
                    qr.print_ascii(out=buf, invert=True)
                    qr_text = buf.getvalue()
                except Exception:
                    qr_text = ""

                timeout_mins = settings.DEVICE_AUTH_TIMEOUT // 60
                msg = (
                    f"\n|wThis account uses passwordless login.|n\n"
                    f"Scan the QR code below on your phone to sign in "
                    f"(expires in {timeout_mins} minutes):\n\n"
                )
                if qr_text:
                    msg += qr_text + "\n"
                msg += (
                    f"|wOr visit:|n {url}\n\n"
                    "Waiting for authentication... "
                    "(type |wauth cancel|n to abort)"
                )
                session.msg(msg)

                # Start polling.
                from twisted.internet import reactor
                reactor.callLater(3, _poll_device_auth, session, script_key)
                return
            else:
                # Password-only account or unknown username — show generic error.
                session.msg("\n\r Usage (without <>): connect <name> <password>")
                return

        if len(parts) != 2:
            session.msg("\n\r Usage (without <>): connect <name> <password>")
            return
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
uv run pytest evennia/commands/tests/test_unloggedin_device_auth.py -v
```

Expected: 3 PASSED.

- [ ] **Step 6: Commit**

```bash
git add evennia/commands/default/unloggedin.py \
        evennia/commands/tests/__init__.py \
        evennia/commands/tests/test_unloggedin_device_auth.py
git commit -m "feat: add device-auth branch to CmdUnconnectedConnect and _poll_device_auth"
```

---

## Task 4: `CmdUnconnectedDeviceAuth` and cmdset registration

**Files:**
- Modify: `evennia/commands/default/unloggedin.py`
- Modify: `evennia/commands/default/cmdset_unloggedin.py`

- [ ] **Step 1: Add the command to `unloggedin.py`**

Add after `CmdUnconnectedTOTP`:

```python
class CmdUnconnectedDeviceAuth(COMMAND_DEFAULT_CLASS):
    """
    Manage a pending device-auth (QR code) login.

    Usage (at login screen, while waiting for QR authentication):
      auth cancel

    Cancels the current pending QR authentication and returns you to
    the login prompt. Use 'connect <username>' to start a new attempt.
    """

    key = "auth"
    aliases = ["device"]
    locks = "cmd:all()"
    arg_regex = r"\s.*?|$"

    def func(self):
        """Handle auth subcommands."""
        session = self.caller
        arg = self.args.strip().lower()

        if arg != "cancel":
            session.msg("Usage: |wauth cancel|n")
            return

        script_key = session.ndb._pending_auth_script_key
        if not script_key:
            session.msg("No pending authentication to cancel.")
            return

        from evennia.server.pending_auth import get_pending_script

        token = script_key.replace("pending_auth_", "")
        script = get_pending_script(token)
        if script:
            script.delete()
        session.ndb._pending_auth_script_key = None
        session.msg("Authentication cancelled. Use |wconnect <username>|n to try again.")
```

Also add `CmdUnconnectedDeviceAuth` to `__all__` in `unloggedin.py`:

```python
__all__ = (
    "CmdUnconnectedConnect",
    "CmdUnconnectedTOTP",
    "CmdUnconnectedDeviceAuth",
    "CmdUnconnectedCreate",
    "CmdUnconnectedQuit",
    "CmdUnconnectedLook",
    "CmdUnconnectedHelp",
    "CmdUnconnectedEncoding",
    "CmdUnconnectedInfo",
    "CmdUnconnectedScreenreader",
)
```

- [ ] **Step 2: Register the command in `cmdset_unloggedin.py`**

In `evennia/commands/default/cmdset_unloggedin.py`, add after the `CmdUnconnectedTOTP` line:

```python
        self.add(unloggedin.CmdUnconnectedDeviceAuth())
```

- [ ] **Step 3: Add a test for auth cancel**

Append to `evennia/commands/tests/test_unloggedin_device_auth.py`:

```python
class TestCmdUnconnectedDeviceAuth(BaseEvenniaTestCase):
    """Tests for the auth cancel command."""

    def test_cancel_with_pending_script(self):
        """auth cancel deletes the pending script and clears session state."""
        from evennia.commands.default.unloggedin import CmdUnconnectedDeviceAuth
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script
        import time

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
```

- [ ] **Step 4: Run tests**

```bash
uv run pytest evennia/commands/tests/test_unloggedin_device_auth.py -v
```

Expected: 5 PASSED.

- [ ] **Step 5: Commit**

```bash
git add evennia/commands/default/unloggedin.py \
        evennia/commands/default/cmdset_unloggedin.py \
        evennia/commands/tests/test_unloggedin_device_auth.py
git commit -m "feat: add CmdUnconnectedDeviceAuth (auth cancel) and register in cmdset"
```

---

## Task 5: Web views — `device_auth` and `device_complete`

**Files:**
- Modify: `evennia/web/website/views/accounts.py`
- Create: `evennia/web/templates/website/device_auth_complete.html`
- Create: `evennia/web/templates/website/device_auth_expired.html`
- Modify: `evennia/web/website/urls.py`
- Create: `evennia/web/utils/tests/test_device_auth_views.py`

`device_auth` is the QR landing page. It looks up the script, stores the token in the session,
then redirects to allauth's login page with `?next=` pointing at `device_complete`. The login
page already hides the password form when the next URL contains `/auth/device/` (added in Task 6).

`device_complete` is the post-auth callback. It requires the user to be logged in, verifies
the username matches the script, and marks the script complete.

- [ ] **Step 1: Write failing tests**

Create `evennia/web/utils/tests/test_device_auth_views.py`:

```python
"""Tests for device_auth and device_complete views."""
import time

from django.test import TestCase, override_settings
from django.urls import reverse

from evennia.utils.test_resources import BaseEvenniaTestCase


@override_settings(DEVICE_AUTH_TIMEOUT=300)
class TestDeviceAuthView(BaseEvenniaTestCase):
    """Tests for the device_auth landing view."""

    def _make_script(self, token="abcd1234", username=None, expired=False):
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        username = username or self.account.username
        script = create_script(
            PendingAuthScript, key=f"pending_auth_{token}", persistent=False
        )
        script.db.token = token
        script.db.username = username
        script.db.expires_at = time.time() + (-1 if expired else 300)
        script.db.completed = False
        script.db.account_id = None
        return script

    def test_valid_token_redirects_to_login(self):
        """GET /auth/device/<valid_token>/ redirects to login page."""
        script = self._make_script("abcd1234")
        url = reverse("device_auth", kwargs={"token": "abcd1234"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/auth/accounts/login/", resp["Location"])
        self.assertIn("device_complete", resp["Location"])
        script.delete()

    def test_expired_token_shows_error_page(self):
        """GET /auth/device/<expired_token>/ renders the expired template."""
        script = self._make_script("deadbeef", expired=True)
        url = reverse("device_auth", kwargs={"token": "deadbeef"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 410)
        self.assertTemplateUsed(resp, "website/device_auth_expired.html")
        script.delete()

    def test_unknown_token_returns_404(self):
        """GET /auth/device/<unknown>/ returns 404."""
        url = reverse("device_auth", kwargs={"token": "00000000"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 404)


@override_settings(DEVICE_AUTH_TIMEOUT=300)
class TestDeviceCompleteView(BaseEvenniaTestCase):
    """Tests for the device_complete callback view."""

    def _make_script(self, token="abcd1234", username=None, expired=False, completed=False):
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        username = username or self.account.username
        script = create_script(
            PendingAuthScript, key=f"pending_auth_{token}", persistent=False
        )
        script.db.token = token
        script.db.username = username
        script.db.expires_at = time.time() + (-1 if expired else 300)
        script.db.completed = completed
        script.db.account_id = self.account.pk if completed else None
        return script

    def test_authenticated_matching_user_marks_complete(self):
        """Authenticated request with matching username marks script completed."""
        script = self._make_script("abcd1234")
        self.client.force_login(self.account)
        url = reverse("device_complete", kwargs={"token": "abcd1234"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, "website/device_auth_complete.html")
        script.refresh_from_db()
        self.assertTrue(script.db.completed)
        self.assertEqual(script.db.account_id, self.account.pk)
        script.delete()

    def test_wrong_user_returns_403(self):
        """Authenticated request with mismatched username returns 403."""
        script = self._make_script("abcd1234", username="someone_else")
        self.client.force_login(self.account)
        url = reverse("device_complete", kwargs={"token": "abcd1234"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 403)
        script.delete()

    def test_already_completed_returns_400(self):
        """Request for already-completed token returns 400."""
        script = self._make_script("abcd1234", completed=True)
        self.client.force_login(self.account)
        url = reverse("device_complete", kwargs={"token": "abcd1234"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 400)
        script.delete()

    def test_expired_token_returns_410(self):
        """Request for expired token returns 410."""
        script = self._make_script("abcd1234", expired=True)
        self.client.force_login(self.account)
        url = reverse("device_complete", kwargs={"token": "abcd1234"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 410)
        script.delete()

    def test_unauthenticated_request_redirects_to_login(self):
        """Unauthenticated GET redirects to login."""
        script = self._make_script("abcd1234")
        url = reverse("device_complete", kwargs={"token": "abcd1234"})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/auth/accounts/login/", resp["Location"])
        script.delete()
```

- [ ] **Step 2: Run to confirm failure**

```bash
uv run pytest evennia/web/utils/tests/test_device_auth_views.py -v
```

Expected: `NoReverseMatch: Reverse for 'device_auth' not found`

- [ ] **Step 3: Implement views in `evennia/web/website/views/accounts.py`**

Add to the end of the file:

```python
def device_auth(request, token):
    """
    QR code landing page for telnet device-auth.

    Looks up the ``PendingAuthScript`` for the given token. If valid, stores
    the token in the session and redirects to the allauth login page with
    ``?next=`` pointing at ``device_complete``. If expired or not found,
    renders an appropriate error page.

    Args:
        request: Django HttpRequest.
        token (str): 8-character hex token from the QR URL.

    Returns:
        HttpResponse: redirect or error page.
    """
    from django.http import HttpResponse
    from django.shortcuts import redirect
    from django.urls import reverse

    from evennia.server.pending_auth import get_pending_script

    script = get_pending_script(token)
    if script is None:
        from django.http import Http404
        raise Http404("Token not found.")

    if script.is_expired():
        return HttpResponse(
            render_to_string("website/device_auth_expired.html", {}, request=request),
            status=410,
        )

    # Store token so device_complete can read it after login.
    request.session["device_auth_token"] = token

    if request.user.is_authenticated:
        return redirect(reverse("device_complete", kwargs={"token": token}))

    complete_url = reverse("device_complete", kwargs={"token": token})
    login_url = reverse("account_login")
    return redirect(f"{login_url}?next={complete_url}&device_auth=1")


def device_complete(request, token):
    """
    Post-authentication callback for telnet device-auth.

    Called after the player successfully authenticates via OAuth or passkey
    on the web. Verifies the token, checks that the authenticated user matches
    the pending auth username, marks the ``PendingAuthScript`` as completed,
    and renders a confirmation page.

    Args:
        request: Django HttpRequest. User must be authenticated.
        token (str): 8-character hex token.

    Returns:
        HttpResponse: confirmation page or error response.
    """
    from django.contrib.auth.decorators import login_required
    from django.http import HttpResponse
    from django.shortcuts import redirect
    from django.urls import reverse

    from evennia.server.pending_auth import get_pending_script

    if not request.user.is_authenticated:
        login_url = reverse("account_login")
        return redirect(f"{login_url}?next={request.path}")

    script = get_pending_script(token)
    if script is None:
        from django.http import Http404
        raise Http404("Token not found.")

    if script.is_expired():
        return HttpResponse(status=410)

    if script.db.completed:
        return HttpResponse(status=400)

    if request.user.username != script.db.username:
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden("Username mismatch.")

    # Mark the script complete — the telnet poller will pick this up.
    script.complete(request.user)

    # Clear token from session.
    request.session.pop("device_auth_token", None)

    return HttpResponse(
        render_to_string("website/device_auth_complete.html", {}, request=request),
        status=200,
    )
```

Also add `render_to_string` to the imports at the top of `accounts.py`:

```python
from django.template.loader import render_to_string
```

- [ ] **Step 4: Create templates**

Create `evennia/web/templates/website/device_auth_complete.html`:

```html
{% extends "website/base.html" %}

{% block titleblock %}Signed In{% endblock %}

{% block body %}
<div class="container main-content mt-4" id="main-copy">
  <div class="row">
    <div class="col-lg-5 offset-lg-3 col-sm-12">
      <div class="card mt-3">
        <div class="card-body text-center">
          <h1 class="card-title">You're signed in!</h1>
          <hr />
          <p class="text-muted">Return to your terminal — you should be logged in automatically.</p>
        </div>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

Create `evennia/web/templates/website/device_auth_expired.html`:

```html
{% extends "website/base.html" %}

{% block titleblock %}Link Expired{% endblock %}

{% block body %}
<div class="container main-content mt-4" id="main-copy">
  <div class="row">
    <div class="col-lg-5 offset-lg-3 col-sm-12">
      <div class="card mt-3">
        <div class="card-body text-center">
          <h1 class="card-title">Link Expired</h1>
          <hr />
          <p class="text-muted">This sign-in link has expired. Return to your terminal and type <strong>connect &lt;username&gt;</strong> to get a new code.</p>
        </div>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Add URLs to `evennia/web/website/urls.py`**

In `evennia/web/website/urls.py`, add to `urlpatterns` before the `SERVE_MEDIA` block:

```python
    # Telnet device-auth (QR code passwordless login)
    path("auth/device/<str:token>/", views.accounts.device_auth, name="device_auth"),
    path("auth/device/<str:token>/complete/", views.accounts.device_complete, name="device_complete"),
```

Also add the accounts import at the top of the views imports block if not already present:

```python
from .views import channels, characters, errors, accounts
```

- [ ] **Step 6: Run tests**

```bash
uv run pytest evennia/web/utils/tests/test_device_auth_views.py -v
```

Expected: 8 PASSED.

- [ ] **Step 7: Commit**

```bash
git add evennia/web/website/views/accounts.py \
        evennia/web/website/urls.py \
        evennia/web/templates/website/device_auth_complete.html \
        evennia/web/templates/website/device_auth_expired.html \
        evennia/web/utils/tests/test_device_auth_views.py
git commit -m "feat: add device_auth and device_complete views for telnet QR login"
```

---

## Task 6: Hide password form on login page during device-auth

**Files:**
- Modify: `evennia/web/templates/account/login.html`

When the QR URL redirects to the login page with `?device_auth=1`, the player should only
see OAuth and passkey options — not the password form. The login template already has access
to `request.GET` via the template context.

- [ ] **Step 1: Update `login.html`**

In `evennia/web/templates/account/login.html`, wrap the password form with a check:

```html
          {% if not request.GET.device_auth %}
            <form method="post" action="{% url 'account_login' %}">
              {% csrf_token %}
              {{ redirect_field }}

              {% for field in form %}
              <div class="form-group">
                <label for="{{ field.id_for_label }}">{{ field.label }}:</label>
                {{ field|addclass:"form-control" }}
                {% if field.errors %}
                  {% for error in field.errors %}
                    <div class="invalid-feedback d-block">{{ error }}</div>
                  {% endfor %}
                {% endif %}
              </div>
              {% endfor %}

              <hr />
              <div class="row">
                <div class="col-lg-6 col-sm-12 text-center small">
                  <a href="{% url 'account_reset_password' %}">Forgot Password?</a>
                </div>
                <div class="col-lg-6 col-sm-12 text-center small">
                  <a href="{% url 'account_signup' %}">Create Account</a>
                </div>
              </div>
              <hr />

              <div class="form-group">
                <input class="form-control btn btn-outline-secondary" type="submit" value="Login" />
              </div>
            </form>
          {% else %}
            <p class="text-muted small text-center">
              Use your passkey or social account to sign in to your terminal session.
            </p>
          {% endif %}
```

- [ ] **Step 2: Manually verify**

Start the dev server and visit `http://localhost:4001/auth/accounts/login/?device_auth=1`.
Confirm the password form is hidden and the social/passkey options are visible.

- [ ] **Step 3: Commit**

```bash
git add evennia/web/templates/account/login.html
git commit -m "feat: hide password form on login page during device-auth flow"
```

---

## Task 7: Format, lint, and full test run

- [ ] **Step 1: Format**

```bash
make format
```

- [ ] **Step 2: Lint**

```bash
make lint
```

Expected: no errors.

- [ ] **Step 3: Run all new tests**

```bash
uv run pytest \
  evennia/server/tests/test_pending_auth.py \
  evennia/commands/tests/test_unloggedin_device_auth.py \
  evennia/web/utils/tests/test_device_auth_views.py \
  -v
```

Expected: all tests PASSED.

- [ ] **Step 4: Commit formatting if needed**

```bash
git add -p
git commit -m "style: apply black/isort formatting"
```

---

## Summary of commits

1. `feat: add PendingAuthScript for telnet device-auth flow`
2. `feat: add DEVICE_AUTH_TIMEOUT setting for telnet device-auth`
3. `feat: add device-auth branch to CmdUnconnectedConnect and _poll_device_auth`
4. `feat: add CmdUnconnectedDeviceAuth (auth cancel) and register in cmdset`
5. `feat: add device_auth and device_complete views for telnet QR login`
6. `feat: hide password form on login page during device-auth flow`
7. `style: apply black/isort formatting` (if needed)
