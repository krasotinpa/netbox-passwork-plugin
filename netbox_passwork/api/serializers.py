"""API serializers following NetBox convention (<plugin>.api.serializers).

The NetBox events pipeline (webhooks/event rules, also triggered on changelog
operations) serializes the object via
utilities.api.get_serializer_for_model(), which looks up the serializer
specifically in this module by the name <Model>Serializer.
"""

from netbox_passwork.serializers import PassworkBindingSerializer

__all__ = ("PassworkBindingSerializer",)
