import json
import logging

from django.db import transaction
from django.http import JsonResponse
from django.views import View

from netbox_passwork.exceptions import PassworkError
from netbox_passwork.gateway import build_gateway
from netbox_passwork.models import PassworkAuditLog, PassworkBinding
from netbox_passwork.permissions import PLUGIN_PERMISSIONS, RequireNetboxPermMixin
from netbox_passwork.serializers import (
    AuditLogSerializer,
    PassworkBindingSerializer,
)
from netbox_passwork.utils import get_client_ip

logger = logging.getLogger("netbox_passwork")


def _error(code: str, detail: str, status: int) -> JsonResponse:
    """Uniform error body format for the plugin API: {"code", "detail"}."""
    return JsonResponse({"code": code, "detail": detail}, status=status)


class ApiError(Exception):
    """
    A plugin API-level failure (invalid parameters, no binding), raised from a view
    method on the gateway; ``PassworkView.dispatch`` turns it into ``_error`` the same
    way it does ``PassworkError``. Same three fields and the same call shape as
    ``PassworkError`` (``detail`` positional, ``code``/``http_status`` keyword-only), but
    it's not a Passwork failure — hence a separate type (see docs/adr/0001-passwork-gateway-not-middleware.md).
    """

    def __init__(self, detail: str, *, code: str, http_status: int):
        self.detail = detail
        self.code = code
        self.http_status = http_status
        super().__init__(detail)


def _json_body(request) -> dict | None:
    """JSON object from the request body; None — the body isn't JSON or isn't an object."""
    try:
        body = json.loads(request.body)
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _text(body: dict, key: str) -> str:
    """String field of the request body, stripped; missing or not a string → ""."""
    value = body.get(key)
    return value.strip() if isinstance(value, str) else ""


def _reveal_requested(request) -> bool:
    """``?reveal=true`` (case-insensitive) — reveal of the password and secret custom fields was requested."""
    return request.GET.get("reveal", "").lower() == "true"


def _object_id(request) -> int | None:
    """``object_id`` from the query parameters as an int; None — missing or not a number."""
    try:
        return int(request.GET.get("object_id", "").strip())
    except ValueError:
        return None


def _bound_object(request, pw_id: str) -> tuple[str, int]:
    """
    ``(object_type, object_id)`` of the NetBox object, from query parameters, that ``pw_id`` is bound to.

    ``object_id`` not a number → 400 ``invalid_object_id``; no binding → 404 ``binding_not_found``
    (guards against proxying arbitrary secrets: Passwork is never queried).
    """
    object_type = request.GET.get("object_type", "").strip()
    object_id = _object_id(request)
    if object_id is None:
        raise ApiError("object_id must be an integer", code="invalid_object_id", http_status=400)
    if not PassworkBinding.objects.filter(
        object_type=object_type,
        object_id=object_id,
        passwork_item_id=pw_id,
    ).exists():
        raise ApiError("Binding not found", code="binding_not_found", http_status=404)
    return object_type, object_id


def _parse_int(value, default: int, min_val: int = 0) -> int | None:
    """Safely parses an int from a query parameter.
    Returns None if the value is set but isn't a number."""
    if value is None:
        return default
    try:
        return max(min_val, int(value))
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Base view for views that talk to Passwork
# ---------------------------------------------------------------------------


class PassworkView(RequireNetboxPermMixin, View):
    """
    Base view for all views that talk to Passwork (ADR-0001).

    ``dispatch``: NetBox permissions → 405 for an unsupported method → build the gateway
    for the request → if ``requires_passwork_session``, an immediate check/refresh of the
    Passwork session (except OPTIONS) → the view method (gateway available as
    ``self.gateway``) → ``PassworkError``/``ApiError`` → ``{"code", "detail"}`` with the
    status from the exception.

    ``permission_required = None`` — only NetBox authentication (Login/Totp).
    ``gateway_factory`` — a seam for tests: ``as_view(gateway_factory=lambda request: fake)``.
    """

    requires_passwork_session = True
    # staticmethod: the factory is called as self.gateway_factory(request), unbound from self
    gateway_factory = staticmethod(build_gateway)

    def dispatch(self, request, *args, **kwargs):
        denied = self.check_netbox_permissions(request)
        if denied is not None:
            return denied
        method = request.method.lower()
        if method not in self.http_method_names or not hasattr(self, method):
            return self.http_method_not_allowed(request, *args, **kwargs)
        self.gateway = self.gateway_factory(request)
        try:
            if self.requires_passwork_session and method != "options":
                self.gateway.require_session()
            # NetBox permissions already checked — skip the mixin's dispatch, continue the MRO: View.dispatch → view method
            return super(RequireNetboxPermMixin, self).dispatch(request, *args, **kwargs)
        except (PassworkError, ApiError) as exc:
            return _error(exc.code, exc.detail, exc.http_status)


# ---------------------------------------------------------------------------
# Auth views
# ---------------------------------------------------------------------------


class PassworkLoginView(PassworkView):
    """POST /auth/login/ — log in to Passwork via the gateway; no Passwork session needed yet."""

    permission_required = None
    requires_passwork_session = False

    def post(self, request):
        body = _json_body(request)
        if body is None:
            return _error("invalid_json", "Request body must be a JSON object", 400)

        username = _text(body, "username")
        password = _text(body, "password")
        if not username or not password:
            return _error("missing_credentials", "Username and password are required", 400)

        requires_totp = self.gateway.login(username, password)
        if requires_totp:
            return JsonResponse({"status": "totp_required", "requires_totp": True})
        return JsonResponse({"status": "ok", "requires_totp": False})


class PassworkTotpView(PassworkView):
    """POST /auth/totp/ — confirms TOTP for the Passwork session saved at the login step."""

    permission_required = None

    def post(self, request):
        body = _json_body(request)
        if body is None:
            return _error("invalid_json", "Request body must be a JSON object", 400)

        code = _text(body, "code")
        if not code:
            return _error("missing_code", "TOTP code is required", 400)

        self.gateway.confirm_totp(code)
        return JsonResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Secrets list
# ---------------------------------------------------------------------------


class SecretsListView(RequireNetboxPermMixin, View):
    """GET /secrets/?object_type=X&object_id=Y"""

    permission_required = "view_secrets"

    def get(self, request):
        object_type = request.GET.get("object_type", "").strip()
        if not object_type or not request.GET.get("object_id", "").strip():
            return _error("missing_params", "object_type and object_id are required", 400)

        object_id = _object_id(request)
        if object_id is None:
            return _error("invalid_object_id", "object_id must be an integer", 400)

        bindings = PassworkBinding.objects.filter(
            object_type=object_type,
            object_id=object_id,
        ).values("id", "passwork_item_id")

        data = [{"pw_id": b["passwork_item_id"], "binding_id": b["id"]} for b in bindings]
        return JsonResponse(data, safe=False)


# ---------------------------------------------------------------------------
# Secret detail (proxy)
# ---------------------------------------------------------------------------


class SecretDetailView(PassworkView):
    """GET /secrets/{pw_id}/detail/?object_type=X&object_id=Y[&reveal=true]"""

    permission_required = "view_secrets"

    def check_netbox_permissions(self, request):
        """NetBox permissions: ``view_secrets``, and with ``reveal=true`` also ``reveal_secret`` — before the Passwork session check."""
        denied = super().check_netbox_permissions(request)
        if denied is None and _reveal_requested(request):
            if not request.user.has_perm(PLUGIN_PERMISSIONS["reveal_secret"]):
                return _error("netbox_permission_denied", "Permission denied", 403)
        return denied

    def get(self, request, pw_id):
        reveal = _reveal_requested(request)
        object_type, object_id = _bound_object(request, pw_id)  # 400/404 — ApiError → base view

        # Passwork failures (403/504/502/401) are turned into a response by the base view
        item = self.gateway.get_item(pw_id)

        response_data = {
            "pw_id": pw_id,
            "name": item.get("name", ""),
            "login": item.get("login", ""),
            "description": item.get("description", ""),
            "passwork_url": item.get("url", ""),
            "custom_fields": [
                {
                    "name": cf.get("name", ""),
                    "is_secret": cf.get("is_secret", False),
                    "type": cf.get("type", "text"),
                    "value": cf.get("value", "") if (reveal or not cf.get("is_secret", False)) else "",
                }
                for cf in item.get("custom_fields", [])
            ],
        }

        if reveal:
            response_data["password"] = item.get("password", "")
            with transaction.atomic():
                PassworkAuditLog.objects.create(
                    netbox_user=request.user,
                    passwork_item_id=pw_id,
                    object_type=object_type,
                    object_id=object_id,
                    action="reveal",
                    ip_address=get_client_ip(request),
                )

        return JsonResponse(response_data)


# ---------------------------------------------------------------------------
# Copy
# ---------------------------------------------------------------------------


class SecretCopyView(PassworkView):
    """POST /secrets/{pw_id}/copy/?object_type=X&object_id=Y — audits the copy; requires a live Passwork session."""

    permission_required = "reveal_secret"

    def post(self, request, pw_id):
        object_type, object_id = _bound_object(request, pw_id)  # 400/404 — ApiError → base view

        PassworkAuditLog.objects.create(
            netbox_user=request.user,
            passwork_item_id=pw_id,
            object_type=object_type,
            object_id=object_id,
            action="copy",
            ip_address=get_client_ip(request),
        )
        return JsonResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


class BindingsCreateView(RequireNetboxPermMixin, View):
    """POST /bindings/"""

    permission_required = "add_binding"

    def post(self, request):
        body = _json_body(request)
        if body is None:
            return _error("invalid_json", "Request body must be a JSON object", 400)

        object_type = _text(body, "object_type")
        object_id = body.get("object_id")
        passwork_item_id = _text(body, "passwork_item_id")

        if not all([object_type, object_id, passwork_item_id]):
            return _error("missing_params", "object_type, object_id and passwork_item_id are required", 400)

        # Validate object_type against allowed choices
        valid_types = [c[0] for c in PassworkBinding.OBJECT_TYPE_CHOICES]
        if object_type not in valid_types:
            return _error("invalid_object_type", f"object_type must be one of: {', '.join(valid_types)}", 400)

        # Check for a duplicate before saving — return 409 instead of a DB exception
        if PassworkBinding.objects.filter(
            object_type=object_type,
            object_id=object_id,
            passwork_item_id=passwork_item_id,
        ).exists():
            return _error("duplicate_binding", "Binding already exists", 409)

        binding = PassworkBinding(
            object_type=object_type,
            object_id=object_id,
            passwork_item_id=passwork_item_id,
            created_by=request.user,
        )
        binding.save()

        return JsonResponse(
            PassworkBindingSerializer(binding).data,
            status=201,
        )


class BindingsDeleteView(RequireNetboxPermMixin, View):
    """DELETE /bindings/{id}/"""

    permission_required = "delete_binding"

    def delete(self, request, binding_id):
        try:
            binding = PassworkBinding.objects.get(pk=binding_id)
        except PassworkBinding.DoesNotExist:
            return _error("binding_not_found", "Binding not found", 404)

        # Snapshot of the state before deletion — ends up in the prechange_data changelog
        binding.snapshot()
        binding.delete()

        return JsonResponse({"status": "deleted"})


# ---------------------------------------------------------------------------
# Picker
# ---------------------------------------------------------------------------


class PickerFoldersView(PassworkView):
    """GET /picker/folders/ — list of Passwork vaults for the picker modal; body — array of vaults."""

    permission_required = "add_binding"

    def get(self, request):
        # Passwork failures (401/403/504/502) are turned into {"code","detail"} by the base view
        return JsonResponse(self.gateway.list_vaults(), safe=False)


class PickerSearchView(PassworkView):
    """GET /picker/search/?q=... — search Passwork items; body — array of found items."""

    permission_required = "add_binding"

    def get(self, request):
        query = request.GET.get("q", "").strip()
        if not query:
            return _error("missing_query", "Query parameter q is required", 400)

        # URL-encoding the query is the client's responsibility (H1); Passwork failures are turned into a response by the base view
        return JsonResponse(self.gateway.search_items(query), safe=False)


# ---------------------------------------------------------------------------
# Audit & History
# ---------------------------------------------------------------------------


class AuditLogView(RequireNetboxPermMixin, View):
    """GET /audit/"""

    permission_required = "view_auditlog"

    def get(self, request):
        qs = PassworkAuditLog.objects.select_related("netbox_user").order_by("-timestamp")

        # Filtering
        if raw_user := request.GET.get("user"):
            user_id = _parse_int(raw_user, None)
            if user_id is None:
                return _error("invalid_param", "user must be an integer", 400)
            qs = qs.filter(netbox_user_id=user_id)
        if action := request.GET.get("action"):
            qs = qs.filter(action=action)
        if pw_id := request.GET.get("pw_id"):
            qs = qs.filter(passwork_item_id=pw_id)

        # Pagination
        limit = _parse_int(request.GET.get("limit"), 50)
        offset = _parse_int(request.GET.get("offset"), 0)
        if limit is None or offset is None:
            return _error("invalid_param", "limit and offset must be integers", 400)
        if limit < 1:
            return _error("invalid_param", "limit must be >= 1", 400)
        limit = min(limit, 500)
        total = qs.count()
        data = AuditLogSerializer(qs[offset : offset + limit], many=True).data

        return JsonResponse({"count": total, "results": data})
