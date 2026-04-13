# Telnet Device Auth (Passwordless QR Login) Design

**Date:** 2026-04-12
**Branch:** allauth
**Status:** Approved, pending implementation

## Background

Players who registered via OAuth (Google, Discord, etc.) or passkey-only have no usable
password. On the telnet client there was previously no way for them to log in. This feature
adds a QR-code device-auth flow: the telnet session generates a short-lived token, renders
a QR code in the terminal, and polls the DB until a companion web page confirms the player
authenticated on their phone.

This is modelled on the OAuth 2.0 Device Authorization Grant (RFC 8628), adapted for
Evennia's two-process architecture.

## Trigger Condition

`connect <username>` with **no password** is typed at the login prompt. The server:

1. Looks up the account by username (silently, without revealing existence)
2. Checks if the account has no usable password AND has at least one passwordless method
   (OAuth social account OR WebAuthn/passkey authenticator)
3. If yes → device auth flow
4. If the account has a usable password but no password was given → existing
   "Usage: connect <name> <password>" message (no change)
5. If account not found → generic "Username and/or password is incorrect" (no info leak)

`connect <username> <password>` always goes through the existing password path regardless
of what other methods are set up.

## Flow

```
Telnet side                    DB (PendingAuthScript)   Web side
──────────────────────         ───────────────────────  ──────────────────────
connect Griatch             →  create script:
                                 token (8-char hex)
                                 username
                                 expires_at (now + timeout)
                                 completed = False
                                 account_id = None

render QR code (ASCII art)
print URL + waiting message
start callLater(3s, poll)

callLater fires             →  read script
  completed? → login()         (completed=True)     ←  GET /auth/device/<token>/
  expired?   → prompt                                    renders phone login page
  no?        → reschedule                                (OAuth + passkey options)
                                                        user authenticates via allauth
                                                        POST /auth/device/<token>/complete/
                                                          verify request.user.username == script.db.username
                                                          set completed=True, account_id=user.pk
                                                          return 200
```

## Components

### 1. `PendingAuthScript` — `evennia/server/pending_auth.py`

A `DefaultScript` subclass. `persistent=False` (in-memory is fine; tokens are
short-lived). Fields stored in `script.db`:

- `token` (str): 8-character hex string, URL-safe, generated with `secrets.token_hex(4)`
- `username` (str): the account username this token is for
- `expires_at` (float): `time.time() + DEVICE_AUTH_TIMEOUT`
- `completed` (bool): set to `True` by the web callback
- `account_id` (int or None): set to the account's pk on completion

Helper methods:
- `is_expired()` → `time.time() > self.db.expires_at`
- `complete(account)` → set `completed=True`, `account_id=account.pk`

Keyed by token in DB via `script.db.token`. Looked up with
`DefaultScript.objects.filter(db_key="pending_auth_<token>").first()`.

### 2. `CmdUnconnectedConnect` (modified) — `evennia/commands/default/unloggedin.py`

When `connect <username>` is typed with no password:

1. Look up account by username (using `AccountDB.objects.get_account_from_name`)
2. If not found or has usable password → existing flow unchanged
3. If passwordless methods detected:
   - Create `PendingAuthScript`
   - Store `script.id` in `session.ndb._pending_auth_script_id`
   - Cancel any previously pending script for this session
   - Build URL: `https://<SERVER_HOSTNAME>/auth/device/<token>/`
   - Render QR with `qrcode` library (`qrcode.QRCode`, `terminal` factory)
   - Print QR + URL + waiting message
   - Schedule `reactor.callLater(3, _poll_device_auth, session, script.id)`

Passwordless detection:
```python
def _has_passwordless_methods(account):
    from allauth.mfa.models import Authenticator
    from allauth.socialaccount.models import SocialAccount
    has_passkey = Authenticator.objects.filter(
        user=account, type=Authenticator.Type.WEBAUTHN
    ).exists()
    has_oauth = SocialAccount.objects.filter(user=account).exists()
    return has_passkey or has_oauth
```

### 3. `_poll_device_auth` — `evennia/commands/default/unloggedin.py`

A module-level function (not a command) called by `reactor.callLater`:

```python
def _poll_device_auth(session, script_id):
    # If session is gone, clean up and exit
    # If script is gone, session already logged in or cancelled elsewhere
    # If script.is_expired(): delete script, msg session, return
    # If script.db.completed:
    #     account = AccountDB.objects.get(pk=script.db.account_id)
    #     delete script
    #     session.sessionhandler.login(session, account)
    # Else: reactor.callLater(3, _poll_device_auth, session, script_id)
```

### 4. `CmdUnconnectedDeviceAuth` — `evennia/commands/default/unloggedin.py`

Key: `auth`, aliases: `device`.

`auth cancel` — deletes the pending script, cancels nothing (the next `callLater` fires,
finds the script gone, exits cleanly). Prints "Authentication cancelled."

### 5. `device_auth` view — `evennia/web/website/views/accounts.py`

GET `/auth/device/<token>/`

- Look up `PendingAuthScript` by token
- If not found or expired: render an error page ("This link has expired")
- Store token in session: `request.session['device_auth_token'] = token`
- If user is already authenticated: redirect to `device_complete/<token>/`
- Otherwise: redirect to `account_login` with `?next=/auth/device/<token>/complete/`
  so allauth redirects there automatically after a successful login. The login
  template detects the `next` URL containing `/auth/device/` and hides the
  password form, showing only OAuth and passkey options.

### 6. `device_complete` view — `evennia/web/website/views/accounts.py`

GET `/auth/device/<token>/complete/` — rendered after allauth login succeeds.

The `device_auth` view stores the token in `request.session['device_auth_token']`.
A receiver connected to allauth's `user_logged_in` signal checks for this session key
and redirects to `device_complete` after a successful OAuth or passkey login.

- Require `request.user.is_authenticated` (enforce with `@login_required`)
- Read token from URL kwargs
- Look up script by token
- If not found: 404
- If expired: 410
- If `completed` already True: 400
- If `request.user.username != script.db.username`: 403
- Mark complete: `script.complete(request.user)`
- Clear `request.session['device_auth_token']`
- Render "You're signed in! Return to your terminal." page

### 6a. `on_user_logged_in` signal receiver — `evennia/web/utils/allauth_adapter.py`

Connected to `allauth.account.signals.user_logged_in` in `EvenniaWebConfig.ready()`.

```python
def on_user_logged_in(sender, request, user, **kwargs):
    token = request.session.get('device_auth_token')
    if token:
        from django.shortcuts import redirect
        return redirect('device_complete', token=token)
```

Note: allauth's `user_logged_in` signal does not support response returns. Instead,
`device_auth` sets a session flag and the post-login redirect URL is overridden via
allauth's `next` parameter pointing to `device_complete`. The `device_auth` view appends
`?next=/auth/device/<token>/complete/` to the login URL so allauth redirects there
automatically after authentication.

### 7. URL entries — `evennia/web/website/urls.py`

```python
path("auth/device/<str:token>/", views.accounts.device_auth, name="device_auth"),
path("auth/device/<str:token>/complete/", views.accounts.device_complete, name="device_complete"),
```

### 8. Settings — `evennia/settings_default.py`

```python
# Timeout in seconds for telnet device-auth (QR code) sessions.
# After this time the QR code expires and the player must try again.
DEVICE_AUTH_TIMEOUT = 300  # 5 minutes
```

## QR Code Rendering

```python
import qrcode
import qrcode.image.terminal  # built into the qrcode package

qr = qrcode.QRCode()
qr.add_data(url)
qr.make(fit=True)
# Print as ASCII art to terminal
import io
f = io.StringIO()
qr.print_ascii(out=f, invert=True)
session.msg(f.getvalue())
```

The `invert=True` flag produces dark-on-light output suitable for most terminal backgrounds.
Fallback: if `qrcode` is not installed, print the URL only with a note to visit it manually.

## URL Generation

```python
from django.conf import settings
hostname = getattr(settings, 'SERVER_HOSTNAME', 'localhost')
port = getattr(settings, 'WEBSOCKET_CLIENT_PORT', 443)
scheme = 'https' if port == 443 else 'http'
url = f"{scheme}://{hostname}/auth/device/{token}/"
```

Games that run behind a reverse proxy should set `SERVER_HOSTNAME` to their public domain.

## Error Handling

| Situation | Behaviour |
|---|---|
| Account not found | Generic auth failure message (no info leak) |
| Account has usable password, no password given | Existing "Usage: connect <name> <password>" |
| Session disconnects during poll | `_poll_device_auth` detects session gone, deletes script, exits |
| Token expired (telnet side) | Delete script, print "Authentication timed out. Use 'connect username' to try again." |
| Token expired (web side) | 410 response, render "This link has expired" page |
| Wrong user completes URL | 403 |
| Token already completed | 400 |
| Concurrent `connect` calls | Cancel previous script, create new one |
| `auth cancel` | Delete script, print "Authentication cancelled." |

## Testing

Tests go in `evennia/server/tests/test_pending_auth.py` and
`evennia/commands/tests/test_unloggedin.py`.

### Test 1: `PendingAuthScript` (no-DB unit)
- `is_expired()` returns False when fresh, True when past expiry
- `complete(account)` sets `completed=True` and `account_id`
- Token is 8 hex characters

### Test 2: `CmdUnconnectedConnect` (DB-backed)
- Passwordless account → creates `PendingAuthScript`, stores id in `session.ndb`, output contains URL
- Password account, no password given → no script created, usage message shown
- Unknown username → generic auth failure, no script created

### Test 3: `device_complete` view (DB-backed)
- Authenticated request, matching username → `completed=True`, 200
- Mismatched username → 403, `completed` unchanged
- Already completed → 400
- Expired token → 410
- Unknown token → 404

## Settings Reference

| Setting | Default | Description |
|---|---|---|
| `DEVICE_AUTH_TIMEOUT` | `300` | Seconds before a QR token expires |
| `SERVER_HOSTNAME` | `"localhost"` | Used to build the QR URL; set to public domain in production |
