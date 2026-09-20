"""Credentials usable only by the designated SNMP probe, never by the RMM API."""

from dataclasses import dataclass

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import SnmpProbeCredential


@dataclass(frozen=True)
class ProbePrincipal:
    username: str
    is_authenticated: bool = True


class SnmpProbeAuthentication(BaseAuthentication):
    def authenticate(self, request):
        key = request.META.get("HTTP_X_API_KEY", "")
        if not isinstance(key, str) or len(key) != 64:
            raise AuthenticationFailed("Invalid probe credential.")

        credential = (
            SnmpProbeCredential.objects.select_related("agent").filter(key=key).first()
        )
        if credential is None or credential.agent.site_id != credential.site_id:
            raise AuthenticationFailed("Invalid probe credential.")

        return ProbePrincipal(username=f"snmp-probe:{credential.agent_id}"), credential

    def authenticate_header(self, request):
        return "X-API-KEY"
