"""
Custom allauth adapter for Evennia.

Routes account creation through Evennia's DefaultAccount.create() so that
typeclass setup, channel joins, and character creation all happen correctly.
Also wires NEW_ACCOUNT_REGISTRATION_ENABLED into allauth's signup gate, and
replaces allauth's username validation with Evennia's own validators.
"""

import secrets

from django.conf import settings
from django.core.exceptions import ValidationError

from allauth.account.adapter import DefaultAccountAdapter


def _get_account_typeclass():
    """Return the configured account typeclass (DefaultAccount subclass)."""
    from evennia.utils import class_from_module

    return class_from_module(
        settings.BASE_ACCOUNT_TYPECLASS, fallback=settings.FALLBACK_ACCOUNT_TYPECLASS
    )


class EvenniaAccountAdapter(DefaultAccountAdapter):
    """
    Allauth adapter that integrates with Evennia's account system.

    Overrides:
    - is_open_for_signup: respects NEW_ACCOUNT_REGISTRATION_ENABLED
    - clean_username: runs Evennia's AUTH_USERNAME_VALIDATORS
    - save_user: creates accounts via DefaultAccount.create() for proper
      typeclass/channel/character initialisation
    """

    def is_open_for_signup(self, request):
        return getattr(settings, "NEW_ACCOUNT_REGISTRATION_ENABLED", True)

    def clean_username(self, username, shallow=False):
        """
        Validate username against Evennia's AUTH_USERNAME_VALIDATORS.

        When shallow=True allauth is probing for a valid generated username;
        the availability validator still runs, which is correct — we don't
        want to suggest usernames that are already taken in Evennia's DB.
        """
        AccountTypeclass = _get_account_typeclass()
        valid, errors = AccountTypeclass.validate_username(username)
        if not valid:
            raise ValidationError(errors[0] if errors else "Invalid username.")
        return username

    def save_user(self, request, user, form, commit=True):
        """
        Create an Evennia account via DefaultAccount.create() so that typeclass
        assignment, default channel joins, and character creation (for
        MULTISESSION_MODE < 2) all fire correctly.

        For social-account signups the form has no password field; in that case
        a random placeholder is used and immediately replaced with an unusable
        password so the account cannot be logged into via password.
        """
        AccountTypeclass = _get_account_typeclass()

        data = form.cleaned_data
        username = data.get("username", "")
        password = data.get("password1") or data.get("password")
        email = data.get("email") or ""

        # Derive the client IP for throttle / ban checks inside create().
        from allauth.core.internal.httpkit import get_client_ip

        ip = get_client_ip(request) or ""

        if not password:
            # Social signup: generate a throwaway password that passes
            # Evennia's validators (length >= 8, not all-numeric, not common).
            password = secrets.token_hex(16)
            social_signup = True
        else:
            social_signup = False

        account, errors = AccountTypeclass.create(
            username=username,
            password=password,
            email=email,
            ip=ip,
        )

        if not account:
            raise ValidationError(errors[0] if errors else "Account creation failed.")

        if social_signup:
            account.set_unusable_password()
            account.save(update_fields=["password"])

        # allauth's BaseSignupForm.save() discards our return value and
        # continues to use the `user` object it passed in.  Populate it
        # in-place so allauth sees a saved object with a valid pk.  This
        # is required for passkey signup, which serialises the login into
        # the session (via stash_login) before the WebAuthn ceremony
        # completes — serialisation calls user_pk_to_url_str(user), which
        # does int(user.pk) and crashes when pk is None.
        user.__dict__.update(account.__dict__)

        return account
