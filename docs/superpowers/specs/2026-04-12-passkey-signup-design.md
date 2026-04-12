# Passkey Signup Design

**Date:** 2026-04-12
**Branch:** allauth
**Status:** Approved, pending implementation

## Background

Evennia's `allauth` branch enabled passkey *login* (`MFA_PASSKEY_LOGIN_ENABLED = True`) but
left passkey *signup* disabled (`MFA_PASSKEY_SIGNUP_ENABLED = False`). The blocker was that
allauth's built-in system check fires `Critical` errors when `MFA_PASSKEY_SIGNUP_ENABLED = True`,
requiring mandatory email verification — which Evennia does not use
(`ACCOUNT_EMAIL_VERIFICATION = "none"`).

Those checks exist because allauth's passkey-signup state is stored in the session; if email
verification sends a link that invalidates the session, the state is lost. With
`ACCOUNT_EMAIL_VERIFICATION = "none"` there is no verification step and therefore no session
loss, so the check is overly conservative for Evennia.

## Goal

Allow players to create an Evennia account using only a username and a passkey (no password),
gated on `MFA_PASSKEY_SIGNUP_ENABLED`. All other MFA and allauth settings must be respected
as-is.

## Flow

1. Player visits `/auth/accounts/signup/passkey/` — allauth's built-in `SignupByPasskeyView`.
2. Player enters a username (password fields absent because `by_passkey=True`).
3. `EvenniaAccountAdapter.save_user()` is called → `DefaultAccount.create()` → typeclass
   assignment, default channel joins, and character creation all fire correctly. A random
   unusable password is set (same path as social/OAuth signup).
4. `complete_signup(by_passkey=True)` marks `login.state["passkey_signup"] = True`.
5. `PasskeySignupStage` intercepts the login pipeline and redirects to
   `/auth/mfa/webauthn/signup/`.
6. Player registers their passkey credential.
7. Account is fully live and the player is logged in.

## Components

### 1. `EvenniaAccountAdapter.get_login_stages()` — `evennia/web/utils/allauth_adapter.py`

Override to include `PasskeySignupStage` when `MFA_PASSKEY_SIGNUP_ENABLED = True` and
`webauthn` is in `MFA_SUPPORTED_TYPES`, bypassing the default guard that allauth ties to
the system check. All other stages (email verification, TOTP authenticate, trust) are
delegated to `super()`.

```python
def get_login_stages(self):
    from allauth.mfa import app_settings as mfa_settings
    from allauth.mfa.models import Authenticator

    # Build stages via super(), which gates PasskeySignupStage on
    # mfa_settings.PASSKEY_SIGNUP_ENABLED internally. We call super() with
    # the setting already True (we've handled the system check separately),
    # so the stage gets added by allauth's own logic — no double-append needed.
    return super().get_login_stages()
```

In practice, `super().get_login_stages()` in allauth's `DefaultAccountAdapter` already
appends `PasskeySignupStage` when `PASSKEY_SIGNUP_ENABLED` is True. Our override is only
needed if we must add the stage when the setting is False (which we do not — we respect the
setting). Therefore, **no override of `get_login_stages()` is required at all**. The entire
purpose of this component is achieved by the system check swap: once the check no longer
blocks startup, setting `MFA_PASSKEY_SIGNUP_ENABLED = True` makes allauth wire everything
up automatically.

### 2. Evennia-aware system check — `evennia/web/utils/allauth_checks.py` (new file)

Replaces allauth's `allauth.mfa.checks.settings_check`. Runs all the same validations but
skips the three email-related criticals when `ACCOUNT_EMAIL_VERIFICATION == "none"`, because
no verification step means no session loss.

Criticals that are suppressed under `EMAIL_VERIFICATION = "none"`:
- `MFA_PASSKEY_SIGNUP_ENABLED requires ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED`
- `MFA_PASSKEY_SIGNUP_ENABLED requires ACCOUNT_SIGNUP_FIELDS to contain 'email*'`
- `MFA_PASSKEY_SIGNUP_ENABLED requires ACCOUNT_EMAIL_VERIFICATION = 'mandatory'`

The one critical that always fires regardless:
- `MFA_PASSKEY_SIGNUP_ENABLED requires MFA_SUPPORTED_TYPES to include 'webauthn'`

### 3. Check swap in `AppConfig.ready()` — `evennia/apps.py`

```python
def ready(self):
    from django.core.checks import registry as checks_registry
    from allauth.mfa.checks import settings_check as _allauth_mfa_check
    from evennia.web.utils.allauth_checks import evennia_mfa_settings_check

    checks_registry.registered_checks.discard(_allauth_mfa_check)
    checks_registry.register(evennia_mfa_settings_check)
```

### 4. Template: `account/signup_by_passkey.html`

Username-only signup form. Extends `website/base.html`. Matches the style of
`account/signup.html` but omits the password fields and includes a brief explanation
("No password needed — your device will be your key.").

### 5. Template: `mfa/webauthn/signup_form.html`

Passkey credential registration step shown after the username form. Mirrors
`mfa/webauthn/add_form.html` in structure and JS wiring. Uses the `mfa_signup_webauthn`
URL action and the `allauth.webauthn.forms.signupForm` JS handler.

### 6. Template: `account/signup.html` update

Add a "Sign up with a passkey instead" link/button below the regular form, visible only when
`PASSKEY_SIGNUP_ENABLED` is true (available in template context via allauth's
`get_entrance_context_data`).

### 7. `settings_default.py` comment update

Update the `MFA_PASSKEY_SIGNUP_ENABLED` comment to document that setting it `True` now works
correctly in Evennia (the system check is replaced with an Evennia-aware version).

## Error Handling

- **Signup form errors** (duplicate username, validation failures): handled by allauth's
  `SignupByPasskeyView` and surfaced via the form. No changes needed.
- **Credential registration failure** (bad credential, timeout, browser cancel): owned by
  allauth's `SignupWebAuthnView`. No changes needed.
- **Abandoned signup** (username registered but passkey step skipped): account exists with
  unusable password and no passkey. Same state as an abandoned social/OAuth signup. Recovery
  via password reset (if email is set) or admin intervention.

## Testing

Tests go in `evennia/web/tests/test_allauth_adapter.py` (extend or create).
Write tests before implementation (TDD).

### Test 1: `get_login_stages()` gating (no-DB)
- `MFA_PASSKEY_SIGNUP_ENABLED = True`, `webauthn` in supported types →
  `PasskeySignupStage` in returned list.
- `MFA_PASSKEY_SIGNUP_ENABLED = False` → `PasskeySignupStage` not in list.

### Test 2: Evennia-aware system check (no-DB)
- `ACCOUNT_EMAIL_VERIFICATION = "none"`, `MFA_PASSKEY_SIGNUP_ENABLED = True`,
  `webauthn` in supported types → check returns no errors.
- `ACCOUNT_EMAIL_VERIFICATION = "none"`, `MFA_PASSKEY_SIGNUP_ENABLED = True`,
  `webauthn` NOT in supported types → check returns the webauthn critical.
- `ACCOUNT_EMAIL_VERIFICATION = "mandatory"`, misconfigured email fields →
  check still returns the email-related criticals (normal allauth behaviour).

### Test 3: Passkey signup flow (DB-backed)
- POST to `account_signup_by_passkey` with a valid username.
- Assert a `DefaultAccount` was created with the correct typeclass.
- Assert the account has an unusable password.
- Assert `login.state["passkey_signup"] == True` (inspect session or login state).
- Assert the account joined the default channels.

## Settings

No new settings. Existing settings that govern this feature:

| Setting | Default | Effect |
|---|---|---|
| `MFA_PASSKEY_SIGNUP_ENABLED` | `False` | Master switch for passkey signup |
| `MFA_SUPPORTED_TYPES` | `["totp", "recovery_codes", "webauthn"]` | Must include `"webauthn"` |
| `MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN` | `True` | Allows localhost dev without HTTPS |
| `NEW_ACCOUNT_REGISTRATION_ENABLED` | `True` | If False, signup is closed entirely |
