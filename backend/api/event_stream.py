import asyncio
import logging
from typing import Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

EventListener = Callable[[Dict], Awaitable[None]]

_listeners: List[EventListener] = []
_event_loop: Optional[asyncio.AbstractEventLoop] = None


def set_event_loop(loop: asyncio.AbstractEventLoop):
    global _event_loop
    _event_loop = loop


def clear_event_loop():
    global _event_loop
    _event_loop = None


def register_listener(listener: EventListener):
    if listener not in _listeners:
        _listeners.append(listener)


def unregister_listener(listener: EventListener):
    if listener in _listeners:
        _listeners.remove(listener)


async def _publish(packet: Dict):
    for listener in list(_listeners):
        try:
            await listener(packet)
        except Exception as exc:
            logger.error(f"Failed to publish event stream packet: {exc}")


def publish_sync(packet_type: str, payload: Dict):
    if not _listeners or _event_loop is None or not _event_loop.is_running():
        return
    packet = {"type": packet_type, "payload": payload}
    _event_loop.call_soon_threadsafe(asyncio.create_task, _publish(packet))
