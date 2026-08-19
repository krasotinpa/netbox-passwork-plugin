from rest_framework import serializers

from netbox_passwork.models import PassworkAuditLog, PassworkBinding


class PassworkBindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = PassworkBinding
        fields = [
            "id",
            "object_type",
            "object_id",
            "passwork_item_id",
            "created",
            "created_by",
        ]
        read_only_fields = ["id", "created", "created_by"]


class SecretListItemSerializer(serializers.Serializer):
    pw_id = serializers.CharField()


class CustomFieldSerializer(serializers.Serializer):
    name = serializers.CharField()
    value = serializers.CharField(allow_null=True, required=False)
    is_secret = serializers.BooleanField(default=False)


class SecretDetailSerializer(serializers.Serializer):
    pw_id = serializers.CharField()
    name = serializers.CharField()
    login = serializers.CharField(allow_blank=True, required=False)
    description = serializers.CharField(allow_blank=True, required=False)
    password = serializers.CharField(allow_null=True, required=False)
    custom_fields = CustomFieldSerializer(many=True, required=False)
    passwork_url = serializers.CharField(required=False)


class AuditLogSerializer(serializers.ModelSerializer):
    netbox_user = serializers.StringRelatedField()

    class Meta:
        model = PassworkAuditLog
        fields = [
            "id",
            "timestamp",
            "netbox_user",
            "passwork_item_id",
            "object_type",
            "object_id",
            "action",
            "ip_address",
        ]
