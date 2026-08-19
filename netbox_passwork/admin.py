from django.contrib import admin

from netbox_passwork.models import PassworkAuditLog, PassworkBinding


@admin.register(PassworkBinding)
class PassworkBindingAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "object_type",
        "object_id",
        "passwork_item_id",
        "created",
        "created_by",
    ]
    list_filter = ["object_type"]
    search_fields = ["passwork_item_id", "object_id"]
    readonly_fields = [
        "id",
        "object_type",
        "object_id",
        "passwork_item_id",
        "created",
        "created_by",
    ]
    ordering = ["-created"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(PassworkAuditLog)
class PassworkAuditLogAdmin(admin.ModelAdmin):
    list_display = [
        "id",
        "timestamp",
        "netbox_user",
        "passwork_item_id",
        "object_type",
        "object_id",
        "action",
        "ip_address",
    ]
    list_filter = ["action", "object_type"]
    search_fields = ["passwork_item_id", "netbox_user__username", "object_id"]
    readonly_fields = [
        "id",
        "timestamp",
        "netbox_user",
        "passwork_item_id",
        "object_type",
        "object_id",
        "action",
        "ip_address",
    ]
    ordering = ["-timestamp"]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
