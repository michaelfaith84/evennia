"""Tests for device_auth and device_complete views."""

import time

from django.test import override_settings
from django.urls import reverse

from evennia.utils.test_resources import BaseEvenniaTest


@override_settings(DEVICE_AUTH_TIMEOUT=300)
class TestDeviceAuthView(BaseEvenniaTest):
    """Tests for the device_auth landing view."""

    def _make_script(self, token="abcd1234", username=None, expired=False):
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        username = username or self.account.username
        script = create_script(PendingAuthScript, key=f"pending_auth_{token}", persistent=False)
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
        self.assertIn("/auth/login/", resp["Location"])
        self.assertIn("/auth/device/abcd1234/complete/", resp["Location"])
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
class TestDeviceCompleteView(BaseEvenniaTest):
    """Tests for the device_complete callback view."""

    def _make_script(self, token="abcd1234", username=None, expired=False, completed=False):
        from evennia.server.pending_auth import PendingAuthScript
        from evennia.utils.create import create_script

        username = username or self.account.username
        script = create_script(PendingAuthScript, key=f"pending_auth_{token}", persistent=False)
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
        self.assertIn("/auth/login/", resp["Location"])
        script.delete()
