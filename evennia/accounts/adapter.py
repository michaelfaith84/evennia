from allauth.account.adapter import DefaultAccountAdapter

from evennia import settings
from evennia.accounts.accounts import DefaultAccount
from evennia.server.signals import SIGNAL_ACCOUNT_POST_CREATE
from evennia.utils import class_from_module


class EvenniaAccountAdapter(DefaultAccountAdapter):
    def new_user(self, request):
        user = class_from_module(
            settings.BASE_ACCOUNT_TYPECLASS, fallback=settings.FALLBACK_ACCOUNT_TYPECLASS
        )()

        return user

    # def save_user(self, request, user, form, commit=True):
    #     super().save_user(request, user, form, commit)
    #     permissions = settings.PERMISSION_ACCOUNT_DEFAULT
    #     user.db.FIRST_LOGIN = True
    #     user.permissions.add(permissions)
    #
    #     SIGNAL_ACCOUNT_POST_CREATE.send(sender=user, ip="127.0.0.1")
    #
    #     return user


