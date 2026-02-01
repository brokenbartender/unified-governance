from __future__ import annotations

from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .client import Client


class EnforcementMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        client: Client,
        policy_id: str,
        resource_id_resolver: Callable[[Request], str],
        principal_resolver: Callable[[Request], str],
        action_resolver: Callable[[Request], str],
    ) -> None:
        super().__init__(app)
        self.client = client
        self.policy_id = policy_id
        self.resource_id_resolver = resource_id_resolver
        self.principal_resolver = principal_resolver
        self.action_resolver = action_resolver

    async def dispatch(self, request: Request, call_next):
        resource_id = self.resource_id_resolver(request)
        principal = self.principal_resolver(request)
        action = self.action_resolver(request)
        decision = self.client.enforce(
            policy_id=self.policy_id,
            principal=principal,
            action=action,
            resource_id=resource_id,
        )
        if decision and decision.get("decision") == "deny":
            return Response(content="Access denied", status_code=403)
        return await call_next(request)
