"""NetBox configuration for running the plugin's test suite.

Copy (or symlink) this file to `netbox/netbox/netbox/configuration.py` of a NetBox
checkout, or point `NETBOX_CONFIGURATION` at it. Every value can be overridden through
environment variables, which is what the CI workflow does — see .github/workflows/ci.yml
and docs/development.md.

The Passwork settings below are placeholders: no test ever talks to a real Passwork
instance (the API is mocked with `responses`), but `PASSWORK_URL` and
`SESSION_ENCRYPT_KEY` are required settings of the plugin, so Django refuses to start
without them.
"""

import os

ALLOWED_HOSTS = ["*"]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "netbox"),
        "USER": os.getenv("DB_USER", "netbox"),
        "PASSWORD": os.getenv("DB_PASSWORD", "netbox"),
        "HOST": os.getenv("DB_HOST", "localhost"),
        "PORT": os.getenv("DB_PORT", "5432"),
        "CONN_MAX_AGE": 300,
    }
}

# Both sections are mandatory: netbox.settings raises ImproperlyConfigured without them.
REDIS = {
    "tasks": {
        "HOST": os.getenv("REDIS_HOST", "localhost"),
        "PORT": int(os.getenv("REDIS_PORT", "6379")),
        "PASSWORD": os.getenv("REDIS_PASSWORD", ""),
        "DATABASE": 0,
        "SSL": False,
    },
    "caching": {
        "HOST": os.getenv("REDIS_HOST", "localhost"),
        "PORT": int(os.getenv("REDIS_PORT", "6379")),
        "PASSWORD": os.getenv("REDIS_PASSWORD", ""),
        "DATABASE": 1,
        "SSL": False,
    },
}

# Test-only value. NetBox rejects a SECRET_KEY shorter than 50 characters.
SECRET_KEY = os.getenv("SECRET_KEY", "netbox-passwork-test-secret-key-not-for-production!")
API_TOKEN_PEPPERS = {1: (SECRET_KEY * 2)[:50]}

PLUGINS = ["netbox_passwork"]
PLUGINS_CONFIG = {
    "netbox_passwork": {
        # Placeholder host: the tests mock every Passwork call.
        "PASSWORK_URL": os.getenv("PASSWORK_URL", "https://passwork.test"),
        # Placeholder Fernet key, valid but meaningless — tests that exercise the real
        # gateway override it with a freshly generated one.
        "SESSION_ENCRYPT_KEY": os.getenv("SESSION_ENCRYPT_KEY", "-2FpQz0F1ekPcktpGqnx06EyAMhXOktpda4fHFQ8Svg="),
        "PASSWORK_VERIFY_SSL": False,
    },
}
