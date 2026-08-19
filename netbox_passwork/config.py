from importlib.metadata import version as _pkg_version

from netbox.plugins import PluginConfig


class NetboxPassworkConfig(PluginConfig):
    name = "netbox_passwork"
    verbose_name = "NetBox Passwork Integration"
    version = _pkg_version("netbox-passwork")
    author = "Pavel Krasotin"
    author_email = "krasotinpa@gmail.com"
    description = "Passwork secrets integration for NetBox devices, VMs and services"
    base_url = "passwork"
    required_settings = ["PASSWORK_URL", "SESSION_ENCRYPT_KEY"]
    default_settings = {
        "PASSWORK_VERIFY_SSL": True,
        "TOKEN_REFRESH_MARGIN": 60,
        "PASSWORK_REQUEST_TIMEOUT": 5,
        "SECRET_REVEAL_TIMEOUT": 30,
    }
    min_version = "4.5"

    def ready(self):
        from netbox_passwork.template_extensions import _register_views

        _register_views()


config = NetboxPassworkConfig
