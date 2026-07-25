import os

from channels.routing import ProtocolTypeRouter, URLRouter  # isort:skip
from django.core.asgi import get_asgi_application  # isort:skip

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tacticalrmm.settings")  # isort:skip
django_asgi_app = get_asgi_application()  # isort:skip

from tacticalrmm.utils import KnoxAuthMiddlewareStack  # isort:skip # noqa
from qdt_mcp.server import mcp_asgi_app  # isort:skip # noqa
from .urls import ws_urlpatterns  # isort:skip # noqa


async def http_router(scope, receive, send):
    app = mcp_asgi_app if scope["path"].startswith("/mcp") else django_asgi_app
    await app(scope, receive, send)


application = ProtocolTypeRouter(
    {
        "http": http_router,
        "websocket": KnoxAuthMiddlewareStack(URLRouter(ws_urlpatterns)),
        # required by the mcp app's session manager; django ignores lifespan
        "lifespan": mcp_asgi_app,
    }
)
