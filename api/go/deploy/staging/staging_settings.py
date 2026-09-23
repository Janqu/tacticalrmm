"""Install as /opt/trmm-staging/django/tacticalrmm/staging_settings.py.

Use DJANGO_SETTINGS_MODULE=tacticalrmm.staging_settings. The sibling
local_settings.py must contain exactly LOCAL_SETTINGS_SCAFFOLD below. Never copy
production local_settings.py, private files, database contents or Redis data.

Required environment: DJANGO_SECRET_KEY, STAGING_DB_PASSWORD,
STAGING_MESH_USERNAME, STAGING_MESH_TOKEN_KEY, ROOT_USER. The secret must also
configure staging Go and the staging NATS tacticalrmm account. MeshCentral's own
administrator password is configured separately, never inherited here.

Keep Celery workers/beat, Go scheduled jobs and Mesh sync workers stopped.
celery.py defines its beat schedule directly; no Django setting disables that
schedule. Django's locmem email backend does not intercept the application's
direct SMTP, Matrix or webhook clients: use a fresh DB with no delivery settings
and restrict outbound connectivity separately before exposing this staging API.
"""

import os as _os
from pathlib import Path as _Path


LOCAL_SETTINGS_SCAFFOLD = (
    "from .staging_settings import STAGING_BASE\n"
    "globals().update(STAGING_BASE)\n"
)


def _required(name):
    value = _os.environ.get(name, "")
    if not value:
        raise RuntimeError("Missing isolated staging setting: " + name)
    return value


if "GHACTIONS" in _os.environ:
    raise RuntimeError("GHACTIONS must not be set for staging")

_local = _Path(__file__).with_name("local_settings.py")
if not _local.is_file() or _local.read_text() != LOCAL_SETTINGS_SCAFFOLD:
    raise RuntimeError("Staging requires its exact local_settings.py scaffold; refusing other settings")

_secret = _required("DJANGO_SECRET_KEY")
if len(_secret) < 32:
    raise RuntimeError("DJANGO_SECRET_KEY must be a new staging secret of at least 32 characters")

# helpers.py gives these environment variables precedence over Django settings.
for _name in ("NATS_CONNECT_HOST", "NATS_STD_BIND_HOST", "NATS_WS_BIND_HOST"):
    if _name in _os.environ and _os.environ[_name] != "127.0.0.1":
        raise RuntimeError("Staging NATS must stay on loopback: " + _name)

STAGING_BASE = {
    "SECRET_KEY": _secret,
    "ROOT_USER": _required("ROOT_USER"),
    "ALLOWED_HOSTS": ["api2.q-dt.de"],
    "CORS_ORIGIN_WHITELIST": ["https://rmm2.q-dt.de"],
    "DATABASES": {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": "trmm_staging",
            "USER": "trmm_staging",
            "PASSWORD": _required("STAGING_DB_PASSWORD"),
            "HOST": "127.0.0.1",
            "PORT": "5432",
            "CONN_MAX_AGE": 60,
        }
    },
    # Celery constructs redis:// + REDIS_HOST. Cache/channels are overridden
    # below because base settings append their own default port.
    "REDIS_HOST": "127.0.0.1:6382",
    "MESH_USERNAME": _required("STAGING_MESH_USERNAME"),
    "MESH_TOKEN_KEY": _required("STAGING_MESH_TOKEN_KEY"),
    "MESH_SITE": "https://mesh2.q-dt.de",
    "MESH_WS_URL": "wss://mesh2.q-dt.de",
    "ADMIN_URL": "staging-admin/",
    "TRMM_LOG_TO": "stdout",
    "TRMM_DISABLE_SSO": True,
    "TRMM_DISABLE_SERVER_SCRIPTS": True,
    "TRMM_DISABLE_WEB_TERMINAL": True,
    "TRMM_DISABLE_MESH_SYNC_TASK": True,
}

# Mandatory host/database values are supplied through the checked scaffold
# before base settings derive URLs and construct caches.
from .settings import *  # noqa: E402,F403

DEBUG = False
DEMO = False
ADMIN_ENABLED = False
SWAGGER_ENABLED = False
ALLOWED_HOSTS = ["api2.q-dt.de", "rmm2.q-dt.de"]
CORS_ORIGIN_WHITELIST = ["https://rmm2.q-dt.de"]
CORS_ALLOWED_ORIGINS = CORS_ORIGIN_WHITELIST
CORS_ALLOW_CREDENTIALS = True
CSRF_TRUSTED_ORIGINS = ["https://api2.q-dt.de", "https://rmm2.q-dt.de"]
# Override base settings' q-dt.de domain after importing it. Go must use the
# identical cookie domain; a parent-domain cookie would collide with production.
SESSION_COOKIE_DOMAIN = "api2.q-dt.de"
CSRF_COOKIE_DOMAIN = "api2.q-dt.de"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = True
HEADLESS_FRONTEND_URLS = {
    "socialaccount_login_error": "https://rmm2.q-dt.de/account/provider/callback"
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [("127.0.0.1", 6382)]},
    }
}
CACHES = {
    "default": {
        "BACKEND": "tacticalrmm.cache.TacticalRedisCache",
        "LOCATION": "redis://127.0.0.1:6382/10",
        "OPTIONS": {
            "parser_class": "redis.connection._HiredisParser",
            "pool_class": "redis.BlockingConnectionPool",
            "db": "10",
        },
    }
}
USE_NATS_STANDARD = False  # plain NATS on loopback, TLS at the external proxy
NATS_STANDARD_PORT = 4223
NATS_WEBSOCKET_PORT = 9236
NATS_HTTP_PORT = 8223
NATS_CONNECT_HOST = NATS_STD_BIND_HOST = NATS_WS_BIND_HOST = "127.0.0.1"

EMAIL_BACKEND = "django.core.mail.backends.locmem.EmailBackend"
EMAIL_HOST = "127.0.0.1"
EMAIL_PORT = 1
EMAIL_HOST_USER = EMAIL_HOST_PASSWORD = ""
SERVER_EMAIL = DEFAULT_FROM_EMAIL = "staging@invalid.invalid"

# Never resolve assets or credentials through the production installation.
_private = _Path("/opt/trmm-staging/private")
LOG_DIR = str(_private / "log")
EXE_DIR = str(_private / "exe")
SCRIPTS_DIR = "/opt/trmm-staging/community-scripts"
FIREBASE_CREDENTIALS_FILE = _private / "firebase-disabled.json"
CERT_FILE = "/etc/letsencrypt/live/api2.q-dt.de/fullchain.pem"
KEY_FILE = "/etc/letsencrypt/live/api2.q-dt.de/privkey.pem"
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "trmm": {"handlers": ["console"], "level": "ERROR", "propagate": False},
    },
}
