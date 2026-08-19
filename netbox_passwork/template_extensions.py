from netbox.views.generic import ObjectView
from utilities.views import ViewTab, register_model_view


def _passwork_badge(instance):
    from netbox_passwork.models import PassworkBinding

    type_map = {"device": "device", "virtualmachine": "vm", "service": "service"}
    object_type = type_map.get(instance._meta.model_name)
    if not object_type:
        return 0
    return PassworkBinding.objects.filter(
        object_type=object_type,
        object_id=instance.pk,
    ).count()


class PassworkTabMixin:
    tab = ViewTab(
        label="Passwork",
        badge=_passwork_badge,
        weight=1500,
        hide_if_empty=False,
    )

    def get_extra_context(self, request, instance):
        return {
            "object_type": self.passwork_object_type,
            "object_id": instance.pk,
        }


def _register_views():
    from dcim.models import Device
    from ipam.models import Service
    from virtualization.models import VirtualMachine

    @register_model_view(Device, "passwork", path="passwork")
    class DevicePassworkView(PassworkTabMixin, ObjectView):
        queryset = Device.objects.all()
        template_name = "netbox_passwork/device_passwork.html"
        passwork_object_type = "device"

    @register_model_view(VirtualMachine, "passwork", path="passwork")
    class VMPassworkView(PassworkTabMixin, ObjectView):
        queryset = VirtualMachine.objects.all()
        template_name = "netbox_passwork/vm_passwork.html"
        passwork_object_type = "vm"

    @register_model_view(Service, "passwork", path="passwork")
    class ServicePassworkView(PassworkTabMixin, ObjectView):
        queryset = Service.objects.all()
        template_name = "netbox_passwork/service_passwork.html"
        passwork_object_type = "service"

    return DevicePassworkView, VMPassworkView, ServicePassworkView


template_extensions = []
