# Passkey Signup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable `MFA_PASSKEY_SIGNUP_ENABLED = True` in Evennia so players can create accounts using only a username and a passkey (no password), while respecting all MFA settings.

**Architecture:** The only blocker is allauth's startup system check that requires mandatory email verification when `MFA_PASSKEY_SIGNUP_ENABLED = True`. We replace it with an Evennia-aware version that skips the email-related criticals when `ACCOUNT_EMAIL_VERIFICATION = "none"` (no verification step → no session loss risk). The rest of allauth's passkey signup machinery (`SignupByPasskeyView`, `PasskeySignupStage`, `SignupWebAuthnView`) works as-is with Evennia's existing `EvenniaAccountAdapter.save_user()`.

**Tech Stack:** Django 6.0, django-allauth ≥ 65.0, Evennia's `DefaultAccount.create()`, Bootstrap 5 templates.

**Spec:** `docs/superpowers/specs/2026-04-12-passkey-signup-design.md`

---

## File Map

| Action | Path | Purpose |
|---|---|---|
| Create | `evennia/web/utils/allauth_checks.py` | Evennia-aware replacement for allauth's MFA system check |
| Create | `evennia/web/utils/tests/__init__.py` | Makes the test directory a package |
| Create | `evennia/web/utils/tests/test_allauth_checks.py` | Unit tests for the check function |
| Create | `evennia/web/utils/tests/test_allauth_adapter.py` | Tests for adapter + AppConfig check swap |
| Create | `evennia/web/apps.py` | `EvenniaWebConfig(AppConfig)` — swaps check in `ready()` |
| Create | `evennia/web/templates/account/signup_by_passkey.html` | Username-only signup form (step 1 of passkey signup) |
| Create | `evennia/web/templates/mfa/webauthn/signup_form.html` | Passkey credential registration form (step 2) |
| Modify | `evennia/web/templates/account/signup.html` | Add "Sign up with a passkey" link when feature is enabled |
| Modify | `evennia/settings_default.py` | Set `MFA_PASSKEY_SIGNUP_ENABLED = True`, update comment |

---

## Task 1: Evennia-aware MFA system check

**Files:**
- Create: `evennia/web/utils/tests/__init__.py`
- Create: `evennia/web/utils/tests/test_allauth_checks.py`
- Create: `evennia/web/utils/allauth_checks.py`

The allauth check `allauth.mfa.checks.settings_check` fires four `Critical` errors when
`MFA_PASSKEY_SIGNUP_ENABLED = True`. Three of them require mandatory email verification — not
relevant for Evennia since `ACCOUNT_EMAIL_VERIFICATION = "none"` means there is no
verification step and therefore no session loss. Our replacement keeps the one genuinely
useful critical (webauthn must be in supported types) and skips the three email-related ones
when email verification is off.

- [ ] **Step 1: Create the test package**

```bash
touch evennia/web/utils/tests/__init__.py
```

- [ ] **Step 2: Write failing tests**

Create `evennia/web/utils/tests/test_allauth_checks.py`:

```python
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
```

- [ ] **Step 3: Run to confirm failure**

```bash
cd /path/to/gamedir && uv run pytest evennia/web/utils/tests/test_allauth_checks.py -v
```

Expected: `ModuleNotFoundError: No module named 'evennia.web.utils.allauth_checks'`

- [ ] **Step 4: Implement the check**

Create `evennia/web/utils/allauth_checks.py`:

```python
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
    from allauth.account import app_settings as account_settings
    from allauth.mfa import app_settings
    from allauth.mfa.models import Authenticator

    ret = []

    if not app_settings.PASSKEY_SIGNUP_ENABLED:
        return ret

    # This critical always applies: passkey signup needs the webauthn authenticator.
    if Authenticator.Type.WEBAUTHN not in app_settings.SUPPORTED_TYPES:
        ret.append(
            Critical(
                msg="MFA_PASSKEY_SIGNUP_ENABLED requires MFA_SUPPORTED_TYPES to include 'webauthn'"
            )
        )

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
```

- [ ] **Step 5: Run tests to confirm they pass**

```bash
uv run pytest evennia/web/utils/tests/test_allauth_checks.py -v
```

Expected: 4 tests PASSED.

- [ ] **Step 6: Commit**

```bash
git add evennia/web/utils/allauth_checks.py \
        evennia/web/utils/tests/__init__.py \
        evennia/web/utils/tests/test_allauth_checks.py
git commit -m "feat: add Evennia-aware MFA system check for passkey signup"
```

---

## Task 2: AppConfig that swaps the check at startup

**Files:**
- Create: `evennia/web/apps.py`
- Create/Modify: `evennia/web/utils/tests/test_allauth_adapter.py`

The check swap must happen after all apps are ready (so allauth has already registered its
check) but before Django runs checks. `AppConfig.ready()` is the correct hook. With
`default = True`, Django uses this config automatically when `"evennia.web"` is in
`INSTALLED_APPS` — no changes to `settings_default.py` needed.

- [ ] **Step 1: Write failing test for the check swap**

Create `evennia/web/utils/tests/test_allauth_adapter.py`:

```python
"""Tests for EvenniaAccountAdapter and EvenniaWebConfig check swap."""
from django.test import TestCase


class TestCheckSwap(TestCase):
    """Verify the AppConfig.ready() replaces allauth's MFA check with ours."""

    def test_allauth_check_removed(self):
        """allauth's settings_check must NOT be in the registry after app ready."""
        from allauth.mfa.checks import settings_check as allauth_check
        from django.core.checks import registry as checks_registry

        self.assertNotIn(allauth_check, checks_registry.registered_checks)

    def test_evennia_check_registered(self):
        """Evennia's evennia_mfa_settings_check MUST be in the registry after app ready."""
        from django.core.checks import registry as checks_registry
        from evennia.web.utils.allauth_checks import evennia_mfa_settings_check

        self.assertIn(evennia_mfa_settings_check, checks_registry.registered_checks)
```

- [ ] **Step 2: Run to confirm failure**

```bash
uv run pytest evennia/web/utils/tests/test_allauth_adapter.py::TestCheckSwap -v
```

Expected: 2 FAILED — allauth's check is present and ours is absent.

- [ ] **Step 3: Implement the AppConfig**

Create `evennia/web/apps.py`:

```python
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
        """
        Swap allauth's MFA system check for Evennia's version.

        allauth registers its check in ``allauth.mfa.apps.MFAConfig.ready()``.
        We remove it here and register our own, which relaxes the email-
        verification requirements that do not apply when Evennia's
        ``ACCOUNT_EMAIL_VERIFICATION = "none"``.
        """
        from allauth.mfa.checks import settings_check as _allauth_mfa_check
        from django.core.checks import registry as checks_registry

        from evennia.web.utils.allauth_checks import evennia_mfa_settings_check

        checks_registry.registered_checks.discard(_allauth_mfa_check)
        checks_registry.register(evennia_mfa_settings_check)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
uv run pytest evennia/web/utils/tests/test_allauth_adapter.py::TestCheckSwap -v
```

Expected: 2 PASSED.

- [ ] **Step 5: Commit**

```bash
git add evennia/web/apps.py evennia/web/utils/tests/test_allauth_adapter.py
git commit -m "feat: add EvenniaWebConfig to swap allauth MFA system check at startup"
```

---

## Task 3: Enable passkey signup in default settings

**Files:**
- Modify: `evennia/settings_default.py:1034-1041`

Change the default value to `True` and update the comment to reflect that the system check
is now handled by Evennia.

- [ ] **Step 1: Update the setting**

In `evennia/settings_default.py`, replace lines 1034–1041:

```python
# Passkey login (using a registered security key as the sole credential) is
# safe to enable for existing accounts. Passkey SIGNUP is intentionally left
# disabled: allauth's passkey signup path bypasses EvenniaAccountAdapter.save_user(),
# meaning the account would be created without typeclass assignment, channel
# membership, or character creation. Enable only if you override new_user() and
# complete_signup() in a custom adapter.
MFA_PASSKEY_LOGIN_ENABLED = True
MFA_PASSKEY_SIGNUP_ENABLED = False
```

with:

```python
# Passkey login: players with a registered security key can log in without a password.
MFA_PASSKEY_LOGIN_ENABLED = True
# Passkey signup: players can create an account using only a username and a passkey.
# Evennia's EvenniaWebConfig replaces allauth's system check so that mandatory
# email verification is not required (Evennia uses ACCOUNT_EMAIL_VERIFICATION="none").
MFA_PASSKEY_SIGNUP_ENABLED = True
```

- [ ] **Step 2: Verify the Django check system reports no errors**

The system check tests in Task 1 cover this. You can also run a manual check from an
initialized game directory:

```bash
# From inside an initialized mygame directory with evennia installed:
uv run evennia check 2>&1 | grep -i "passkey\|webauthn\|critical" || echo "No passkey/webauthn criticals"
```

Expected: no output (no passkey/webauthn criticals).

- [ ] **Step 3: Commit**

```bash
git add evennia/settings_default.py
git commit -m "feat: enable MFA_PASSKEY_SIGNUP_ENABLED by default"
```

---

## Task 4: Passkey signup templates

**Files:**
- Create: `evennia/web/templates/account/signup_by_passkey.html`
- Create: `evennia/web/templates/mfa/webauthn/signup_form.html`

Two templates are needed. The first collects the username (step 1). The second handles
passkey credential registration (step 2). Both extend Evennia's `website/base.html` and
use Bootstrap 5 classes consistent with existing templates like `account/signup.html` and
`mfa/webauthn/add_form.html`.

- [ ] **Step 1: Create `account/signup_by_passkey.html`**

This is the first step of passkey signup: user enters a username with no password field.

Create `evennia/web/templates/account/signup_by_passkey.html`:

```html
{% extends "website/base.html" %}
{% load addclass %}

{% block titleblock %}Sign Up with Passkey{% endblock %}

{% block body %}
<div class="container main-content mt-4" id="main-copy">
  <div class="row">
    <div class="col-lg-5 offset-lg-3 col-sm-12">
      <div class="card mt-3">
        <div class="card-body">
          <h1 class="card-title">Sign Up with Passkey</h1>
          <p class="text-muted small">No password needed — your device will be your key.</p>
          <hr />

          {% if form.errors %}
            {% for field in form %}
              {% for error in field.errors %}
                <div class="alert alert-danger" role="alert">{{ error }}</div>
              {% endfor %}
            {% endfor %}
            {% for error in form.non_field_errors %}
              <div class="alert alert-danger" role="alert">{{ error }}</div>
            {% endfor %}
          {% endif %}

          <form method="post" action="{% url 'account_signup_by_passkey' %}">
            {% csrf_token %}
            {{ redirect_field }}

            {% for field in form %}
            <div class="form-field my-3">
              {{ field.label_tag }}
              {{ field|addclass:"form-control" }}
              {% if field.help_text %}
                <small class="form-text text-muted">{{ field.help_text|safe }}</small>
              {% endif %}
            </div>
            {% endfor %}

            <hr />
            <div class="form-group">
              <input class="form-control btn btn-outline-secondary" type="submit" value="Continue" />
            </div>
          </form>

          <div class="text-center mt-2 small">
            <a href="{% url 'account_signup' %}">Sign up with a password instead</a>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 2: Create `mfa/webauthn/signup_form.html`**

This is the second step: the browser prompts the user to register a passkey credential.
The JS wiring uses `allauth.webauthn.forms.signupForm` (distinct from `addForm` used when
adding a key to an existing account).

Create `evennia/web/templates/mfa/webauthn/signup_form.html`:

```html
{% extends "website/base.html" %}
{% load addclass static %}

{% block titleblock %}Register Passkey{% endblock %}

{% block content %}
<div class="row">
  <div class="col-lg-5 offset-lg-3 col-sm-12">
    <div class="card mt-3">
      <div class="card-body">
        <h1 class="card-title">Register Passkey</h1>
        <hr />
        <p>Give your passkey a name, then click <strong>Create Passkey</strong> and follow your browser's prompt.</p>

        <form method="post" action="{% url 'mfa_signup_webauthn' %}" id="webauthn-signup-form">
          {% csrf_token %}
          {% for field in form %}
          <div class="form-group">
            <label for="{{ field.id_for_label }}">{{ field.label }}:</label>
            {{ field|addclass:"form-control" }}
            {% for error in field.errors %}
              <div class="invalid-feedback d-block">{{ error }}</div>
            {% endfor %}
          </div>
          {% endfor %}
          <hr />
          <button type="button" id="mfa_webauthn_signup" class="btn btn-outline-secondary btn-block">
            Create Passkey
          </button>
          <div class="text-center mt-2">
            <a href="{% url 'account_logout' %}">Cancel</a>
          </div>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}

{% block extra_body %}
{% include "mfa/webauthn/snippets/scripts.html" %}
{{ js_data|json_script:"js_data" }}
<script data-allauth-onload="allauth.webauthn.forms.signupForm" type="application/json">{
  "ids": {
    "signup": "mfa_webauthn_signup",
    "credential": "{{ form.credential.auto_id }}",
    "data": "js_data"
  }
}</script>
{% endblock %}
```

- [ ] **Step 3: Commit**

```bash
git add evennia/web/templates/account/signup_by_passkey.html \
        evennia/web/templates/mfa/webauthn/signup_form.html
git commit -m "feat: add passkey signup templates"
```

---

## Task 5: Add "Sign up with passkey" link to the signup page

**Files:**
- Modify: `evennia/web/templates/account/signup.html`

allauth puts `PASSKEY_SIGNUP_ENABLED` and `signup_by_passkey_url` into template context
via `get_entrance_context_data` (called in `SignupView.get_context_data`). We use
`PASSKEY_SIGNUP_ENABLED` to conditionally show the link.

- [ ] **Step 1: Add the passkey link**

In `evennia/web/templates/account/signup.html`, add after the social providers block
(after line 64, just before `{% endif %}` that closes `{% if user.is_authenticated %}`):

```html
            {% if PASSKEY_SIGNUP_ENABLED %}
              <hr />
              <div class="text-center">
                <a href="{% url 'account_signup_by_passkey' %}" class="btn btn-outline-secondary btn-sm">
                  Sign up with a passkey instead
                </a>
              </div>
            {% endif %}
```

The full relevant section of `account/signup.html` after the change should look like:

```html
            {% get_providers as socialaccount_providers %}
            {% if socialaccount_providers %}
              <hr />
              <p class="text-center text-muted small mb-2">Or register with</p>
              <div class="d-flex flex-wrap justify-content-center">
                {% for provider in socialaccount_providers %}
                  {% provider_login_url provider process="login" as provider_url %}
                  <a href="{{ provider_url }}" class="btn btn-outline-secondary btn-sm m-1">
                    {{ provider.name }}
                  </a>
                {% endfor %}
              </div>
            {% endif %}

            {% if PASSKEY_SIGNUP_ENABLED %}
              <hr />
              <div class="text-center">
                <a href="{% url 'account_signup_by_passkey' %}" class="btn btn-outline-secondary btn-sm">
                  Sign up with a passkey instead
                </a>
              </div>
            {% endif %}
          {% endif %}
        </div>
      </div>
    </div>
  </div>
</div>
{% endblock %}
```

- [ ] **Step 2: Commit**

```bash
git add evennia/web/templates/account/signup.html
git commit -m "feat: add passkey signup link to signup page"
```

---

## Task 6: Integration test for passkey signup flow

**Files:**
- Modify: `evennia/web/utils/tests/test_allauth_adapter.py`

This is a DB-backed test. It POSTs to `account_signup_by_passkey`, asserts that
`DefaultAccount.create()` fired correctly (typeclass, channels, unusable password), and
checks that the login state marks `passkey_signup = True`.

- [ ] **Step 1: Add the integration test**

Append to `evennia/web/utils/tests/test_allauth_adapter.py`. The file already imports
`from django.test import TestCase` from Task 2 — add these imports at the top of the
file alongside the existing ones:

```python
from django.test import TestCase, override_settings
from django.urls import reverse

from evennia.utils.test_resources import BaseEvenniaTestCase
```

Then append the test class:


@override_settings(
    MFA_PASSKEY_SIGNUP_ENABLED=True,
    MFA_SUPPORTED_TYPES=["totp", "recovery_codes", "webauthn"],
    ACCOUNT_EMAIL_VERIFICATION="none",
    NEW_ACCOUNT_REGISTRATION_ENABLED=True,
)
class TestPasskeySignupView(BaseEvenniaTestCase):
    """Integration test: POST to signup_by_passkey creates a proper Evennia account."""

    def test_post_creates_account_via_default_account_create(self):
        """
        A POST to account_signup_by_passkey should create a DefaultAccount with:
        - correct typeclass set (not a bare AbstractUser)
        - unusable password (no plaintext credential stored)
        - FIRST_LOGIN attribute set (Evennia post-create hook ran)
        """
        from evennia.accounts.accounts import DefaultAccount

        url = reverse("account_signup_by_passkey")
        response = self.client.post(url, {"username": "testpasskeyuser"}, follow=False)

        # Should redirect to the passkey registration step, not render an error
        self.assertIn(response.status_code, [302, 200])

        account = DefaultAccount.objects.filter(username="testpasskeyuser").first()
        self.assertIsNotNone(account, "Account was not created in the database")

        # Password must be unusable (no plaintext stored)
        self.assertFalse(account.has_usable_password())

        # Evennia's post-create hook must have run
        self.assertTrue(account.db.FIRST_LOGIN)

    def test_post_respects_registration_disabled(self):
        """When NEW_ACCOUNT_REGISTRATION_ENABLED=False, signup returns 403 or redirects."""
        from evennia.accounts.accounts import DefaultAccount

        url = reverse("account_signup_by_passkey")
        with self.settings(NEW_ACCOUNT_REGISTRATION_ENABLED=False):
            response = self.client.post(url, {"username": "shouldnotexist"}, follow=False)

        self.assertNotEqual(response.status_code, 200)
        account = DefaultAccount.objects.filter(username="shouldnotexist").first()
        self.assertIsNone(account, "Account should not be created when registration is disabled")
```

- [ ] **Step 2: Run the integration tests**

```bash
uv run pytest evennia/web/utils/tests/test_allauth_adapter.py -v
```

Expected: `TestCheckSwap` (2 tests) + `TestPasskeySignupView` (2 tests) = 4 PASSED.

Note: if the passkey view tests fail because allauth enforces a stage redirect that Django's
test client doesn't follow correctly, use `follow=True` and check for the
`mfa_signup_webauthn` URL in the redirect chain instead.

- [ ] **Step 3: Commit**

```bash
git add evennia/web/utils/tests/test_allauth_adapter.py
git commit -m "test: add integration tests for passkey signup flow"
```

---

## Task 7: Run full test suite and make format

Run the full suite to catch any regressions, then format.

- [ ] **Step 1: Format**

```bash
make format
```

- [ ] **Step 2: Lint check**

```bash
make lint
```

Expected: no errors.

- [ ] **Step 3: Run all new tests together**

```bash
uv run pytest evennia/web/utils/tests/ -v
```

Expected: all 8 tests PASSED (4 check tests + 2 swap tests + 2 signup flow tests).

- [ ] **Step 4: Final commit if any formatting changes**

```bash
git add -p  # stage only formatting changes
git commit -m "style: apply black/isort formatting"
```

---

## Summary of commits

1. `feat: add Evennia-aware MFA system check for passkey signup`
2. `feat: add EvenniaWebConfig to swap allauth MFA system check at startup`
3. `feat: enable MFA_PASSKEY_SIGNUP_ENABLED by default`
4. `feat: add passkey signup templates`
5. `feat: add passkey signup link to signup page`
6. `test: add integration tests for passkey signup flow`
7. `style: apply black/isort formatting` (if needed)
