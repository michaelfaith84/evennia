"""
Views for managing accounts.

"""

from django.conf import settings
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy

from evennia.utils import class_from_module
from evennia.web.website import forms

from .mixins import EvenniaCreateView, TypeclassMixin


class AccountMixin(TypeclassMixin):
    """
    This is used to grant abilities to classes it is added to.

    Any view class with this in its inheritance list will be modified to work
    with Account objects instead of generic Objects or otherwise.

    """

    # -- Django constructs --
    model = class_from_module(
        settings.BASE_ACCOUNT_TYPECLASS, fallback=settings.FALLBACK_ACCOUNT_TYPECLASS
    )
    form_class = forms.AccountForm


class AccountCreateView(AccountMixin, EvenniaCreateView):
    """
    Account creation view.

    """

    # -- Django constructs --
    template_name = "website/registration/register.html"
    success_url = reverse_lazy("account_login")

    def form_valid(self, form):
        """
        Django hook, modified for Evennia.

        This hook is called after a valid form is submitted.

        When an account creation form is submitted and the data is deemed valid,
        proceeds with creating the Account object.

        """
        # Get values provided
        username = form.cleaned_data["username"]
        password = form.cleaned_data["password1"]
        email = form.cleaned_data.get("email", "")

        # Create account. This also runs all validations on the username/password.
        account, errs = self.typeclass.create(username=username, password=password, email=email)

        if not account:
            # password validation happens earlier, only username checks appear here.
            form.add_error("username", ", ".join(errs))
            return self.form_invalid(form)
        else:
            # Inform user of success
            messages.success(
                self.request, f"Your account '{account.name}' was successfully created!"
            )
            return HttpResponseRedirect(self.success_url)


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
    from django.http import Http404, HttpResponse
    from django.shortcuts import redirect
    from django.urls import reverse

    from evennia.server.pending_auth import get_pending_script

    script = get_pending_script(token)
    if script is None:
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
    from django.http import Http404, HttpResponse, HttpResponseForbidden
    from django.shortcuts import redirect
    from django.urls import reverse

    from evennia.server.pending_auth import get_pending_script

    if not request.user.is_authenticated:
        login_url = reverse("account_login")
        return redirect(f"{login_url}?next={request.path}")

    script = get_pending_script(token)
    if script is None:
        raise Http404("Token not found.")

    if script.is_expired():
        return HttpResponse(status=410)

    if script.db.completed:
        return HttpResponse(status=400)

    if request.user.username != script.db.username:
        return HttpResponseForbidden("Username mismatch.")

    # Mark the script complete — the telnet poller will pick this up.
    script.complete(request.user)

    # Clear token from session.
    request.session.pop("device_auth_token", None)

    return HttpResponse(
        render_to_string("website/device_auth_complete.html", {}, request=request),
        status=200,
    )
