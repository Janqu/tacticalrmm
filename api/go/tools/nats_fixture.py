"""Disposable responder for the isolated, loopback-only Go contract broker."""
import asyncio
from contextlib import contextmanager
import os
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit


def _broker_url():
    value = os.environ.get("TRMM_TEST_NATS_URL", "")
    parsed = urlsplit(value)
    if (parsed.scheme != "nats" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.path or parsed.query or parsed.fragment
            or parsed.username is not None):
        raise ValueError("TRMM_TEST_NATS_URL must identify the isolated loopback NATS test broker")
    # Accessing port also rejects malformed/out-of-range values before starting a thread.
    if parsed.port is None:
        raise ValueError("TRMM_TEST_NATS_URL must include an explicit test port")
    return value


@contextmanager
def responder(subject, replies):
    """Yield a peer whose messages are decoded requests received on one subject.

    Values are MessagePack-encoded; bytes are sent verbatim for malformed-wire
    cases; None intentionally sends no response. A callable receives the decoded
    request before replying, allowing committed-state assertions. The last reply is reused.
    """
    import msgpack
    import nats

    url = _broker_url()
    if not isinstance(subject, str) or not subject or any(c.isspace() or c in "*>" for c in subject):
        raise ValueError("A concrete NATS test subject is required")
    replies = list(replies)
    if not replies:
        raise ValueError("At least one scripted reply is required")
    ready = threading.Event()
    state = {}
    failures = []
    messages = []

    async def serve():
        connection = None
        stop = asyncio.Event()
        state.update(loop=asyncio.get_running_loop(), stop=stop)
        try:
            connection = await nats.connect(
                servers=[url], user="tacticalrmm", password="trmm-test-only",
                connect_timeout=2, allow_reconnect=False,
            )

            async def receive(message):
                try:
                    payload = msgpack.unpackb(message.data, raw=False, strict_map_key=False)
                    messages.append(payload)
                    reply = replies[min(len(messages) - 1, len(replies) - 1)]
                    if callable(reply):
                        reply = reply(payload)
                    if reply is not None:
                        wire = reply if isinstance(reply, bytes) else msgpack.packb(reply, use_bin_type=True)
                        await message.respond(wire)
                except Exception as exc:
                    failures.append(exc)
                    stop.set()

            await connection.subscribe(subject, cb=receive)
            await connection.flush(timeout=2)
            ready.set()
            await stop.wait()
        except Exception as exc:
            failures.append(exc)
        finally:
            ready.set()
            if connection is not None:
                await connection.close()

    def worker():
        try:
            asyncio.run(serve())
        except Exception as exc:
            failures.append(exc)
            ready.set()

    thread = threading.Thread(target=worker, name="trmm-nats-contract-responder", daemon=True)
    thread.start()
    try:
        if not ready.wait(5):
            raise TimeoutError("Local NATS responder did not become ready")
        if failures:
            raise RuntimeError("Local NATS responder failed to start") from failures[0]
        yield SimpleNamespace(messages=messages)
    finally:
        loop, stop = state.get("loop"), state.get("stop")
        if loop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=5)
        if thread.is_alive():
            raise TimeoutError("Local NATS responder did not stop")
    if failures:
        raise RuntimeError("Local NATS responder failed") from failures[0]
