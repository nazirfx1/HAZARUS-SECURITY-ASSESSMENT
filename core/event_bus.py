"""
HAZARUS Event Bus
Asynchronous event system for inter-component communication.
"""

from typing import Dict, Any, Callable, List, Optional
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Event:
    """An event in the system."""
    event_type: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: Optional[str] = None


class EventBus:
    """
    Asynchronous event bus for component communication.
    Uses publish-subscribe pattern.
    """

    def __init__(self):
        self.logger = logging.getLogger("hazarus.event_bus")
        self._subscribers: Dict[str, List[Callable]] = {}
        self._event_history: List[Event] = []
        self._max_history = 1000

    def subscribe(self, event_type: str, handler: Callable) -> None:
        """
        Subscribe to an event type.
        Handler should be an async callable that accepts event data.
        """
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []

        self._subscribers[event_type].append(handler)
        self.logger.debug(f"Subscribed to event: {event_type}")

    def unsubscribe(self, event_type: str, handler: Callable) -> bool:
        """Unsubscribe a handler from an event type."""
        if event_type not in self._subscribers:
            return False

        if handler in self._subscribers[event_type]:
            self._subscribers[event_type].remove(handler)
            self.logger.debug(f"Unsubscribed from event: {event_type}")
            return True

        return False

    async def emit(self, event_type: str, data: Dict[str, Any], source: Optional[str] = None) -> None:
        """
        Emit an event to all subscribers.
        """
        event = Event(event_type=event_type, data=data, source=source)

        # Add to history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        self.logger.debug(f"Emitting event: {event_type}")

        # Notify subscribers
        if event_type in self._subscribers:
            tasks = []
            for handler in self._subscribers[event_type]:
                try:
                    task = asyncio.create_task(handler(event))
                    tasks.append(task)
                except Exception as e:
                    self.logger.error(f"Error in event handler: {e}")

            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def emit_sync(self, event_type: str, data: Dict[str, Any], source: Optional[str] = None) -> None:
        """
        Emit an event and wait for all handlers to complete.
        """
        event = Event(event_type=event_type, data=data, source=source)

        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        self.logger.debug(f"Emitting event (sync): {event_type}")

        if event_type in self._subscribers:
            for handler in self._subscribers[event_type]:
                try:
                    await handler(event)
                except Exception as e:
                    self.logger.error(f"Error in event handler: {e}")

    def get_history(self, event_type: Optional[str] = None, limit: Optional[int] = None) -> List[Event]:
        """
        Get event history.
        If event_type is specified, filter by type.
        If limit is specified, return only the most recent events.
        """
        if event_type:
            events = [e for e in self._event_history if e.event_type == event_type]
        else:
            events = self._event_history.copy()

        if limit:
            events = events[-limit:]

        return events

    def clear_history(self) -> None:
        """Clear event history."""
        self._event_history.clear()
        self.logger.debug("Event history cleared")

    def get_subscriber_count(self, event_type: str) -> int:
        """Get the number of subscribers for an event type."""
        return len(self._subscribers.get(event_type, []))

    def get_all_event_types(self) -> List[str]:
        """Get all registered event types."""
        return list(self._subscribers.keys())
