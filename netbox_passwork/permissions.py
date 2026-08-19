from django.http import JsonResponse

# NetBox ObjectPermissionBackend builds the key as:
# {app_label}.{action}_{model_name}
# All custom plugin permissions are bound to the PassworkBinding model
PLUGIN_PERMISSIONS = {
    "view_secrets": "netbox_passwork.view_secrets_passworkbinding",
    "reveal_secret": "netbox_passwork.reveal_secret_passworkbinding",
    "add_binding": "netbox_passwork.add_binding_passworkbinding",
    "delete_binding": "netbox_passwork.delete_binding_passworkbinding",
    "view_auditlog": "netbox_passwork.view_auditlog_passworkbinding",
}


def require_netbox_perm(perm_key: str):
    def decorator(view_func):
        def wrapper(request, *args, **kwargs):
            perm = PLUGIN_PERMISSIONS.get(perm_key, perm_key)
            if not request.user.is_authenticated:
                return JsonResponse(
                    {"detail": "Authentication required", "code": "not_authenticated"},
                    status=401,
                )
            if not request.user.has_perm(perm):
                return JsonResponse(
                    {"detail": "Permission denied", "code": "netbox_permission_denied"},
                    status=403,
                )
            return view_func(request, *args, **kwargs)

        wrapper.__name__ = view_func.__name__
        wrapper.__module__ = view_func.__module__
        return wrapper

    return decorator


class RequireNetboxPermMixin:
    """
    Checks NetBox permissions before the view method runs.

    ``permission_required`` — a key from PLUGIN_PERMISSIONS (or a full permission name);
    ``None`` — only NetBox authentication is required (Login/Totp).
    """

    permission_required: str | None = ""

    def check_netbox_permissions(self, request) -> JsonResponse | None:
        """None — access allowed; otherwise 401 (no NetBox authentication) or 403 (no permission)."""
        if not request.user.is_authenticated:
            return JsonResponse(
                {"detail": "Authentication required", "code": "not_authenticated"},
                status=401,
            )
        if self.permission_required is not None:
            perm = PLUGIN_PERMISSIONS.get(self.permission_required, self.permission_required)
            if not request.user.has_perm(perm):
                return JsonResponse(
                    {"detail": "Permission denied", "code": "netbox_permission_denied"},
                    status=403,
                )
        return None

    def dispatch(self, request, *args, **kwargs):
        denied = self.check_netbox_permissions(request)
        if denied is not None:
            return denied
        return super().dispatch(request, *args, **kwargs)
