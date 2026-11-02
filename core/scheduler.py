"""
HAZARUS Scheduler
Manages task scheduling and execution timing.
"""

from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timedelta
import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum


class ScheduleStatus(Enum):
    """Schedule status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScheduledTask:
    """A scheduled task."""
    task_id: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    scheduled_time: Optional[datetime] = None
    interval: Optional[timedelta] = None
    status: ScheduleStatus = ScheduleStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None


class Scheduler:
    """
    Task scheduler for timed and periodic operations.
    """

    def __init__(self):
        self.logger = logging.getLogger("hazarus.scheduler")
        self._tasks: Dict[str, ScheduledTask] = {}
        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None

    def schedule_task(
        self,
        task_id: str,
        func: Callable,
        scheduled_time: Optional[datetime] = None,
        interval: Optional[timedelta] = None,
        *args,
        **kwargs
    ) -> ScheduledTask:
        """
        Schedule a task for execution.
        """
        if task_id in self._tasks:
            raise ValueError(f"Task {task_id} already exists")

        task = ScheduledTask(
            task_id=task_id,
            func=func,
            args=args,
            kwargs=kwargs,
            scheduled_time=scheduled_time,
            interval=interval
        )

        self._tasks[task_id] = task
        self.logger.debug(f"Scheduled task: {task_id}")
        return task

    def schedule_immediate(
        self,
        task_id: str,
        func: Callable,
        *args,
        **kwargs
    ) -> ScheduledTask:
        """Schedule a task for immediate execution."""
        return self.schedule_task(task_id, func, datetime.utcnow(), None, *args, **kwargs)

    def schedule_delayed(
        self,
        task_id: str,
        func: Callable,
        delay: timedelta,
        *args,
        **kwargs
    ) -> ScheduledTask:
        """Schedule a task for delayed execution."""
        return self.schedule_task(task_id, func, datetime.utcnow() + delay, None, *args, **kwargs)

    def schedule_periodic(
        self,
        task_id: str,
        func: Callable,
        interval: timedelta,
        *args,
        **kwargs
    ) -> ScheduledTask:
        """Schedule a periodic task."""
        return self.schedule_task(task_id, func, datetime.utcnow(), interval, *args, **kwargs)

    async def start(self) -> None:
        """Start the scheduler."""
        if self._running:
            return

        self._running = True
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        self.logger.info("Scheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        if not self._running:
            return

        self._running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass

        self.logger.info("Scheduler stopped")

    async def _scheduler_loop(self) -> None:
        """Main scheduler loop."""
        while self._running:
            now = datetime.utcnow()

            for task_id, task in list(self._tasks.items()):
                if task.status == ScheduleStatus.PENDING and task.scheduled_time:
                    if now >= task.scheduled_time:
                        await self._execute_task(task)

                elif task.status == ScheduleStatus.COMPLETED and task.interval:
                    # Reschedule periodic tasks
                    task.scheduled_time = now + task.interval
                    task.status = ScheduleStatus.PENDING
                    task.started_at = None
                    task.completed_at = None
                    task.result = None
                    task.error = None

            await asyncio.sleep(0.1)

    async def _execute_task(self, task: ScheduledTask) -> None:
        """Execute a scheduled task."""
        self.logger.debug(f"Executing task: {task.task_id}")
        task.status = ScheduleStatus.RUNNING
        task.started_at = datetime.utcnow()

        try:
            result = await task.func(*task.args, **task.kwargs)
            task.result = result
            task.status = ScheduleStatus.COMPLETED
            task.completed_at = datetime.utcnow()

        except Exception as e:
            task.error = str(e)
            task.status = ScheduleStatus.FAILED
            task.completed_at = datetime.utcnow()
            self.logger.error(f"Task {task.task_id} failed: {e}")

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a scheduled task."""
        if task_id not in self._tasks:
            return False

        task = self._tasks[task_id]
        if task.status in [ScheduleStatus.PENDING, ScheduleStatus.RUNNING]:
            task.status = ScheduleStatus.CANCELLED
            self.logger.debug(f"Cancelled task: {task_id}")
            return True

        return False

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        """Get a scheduled task."""
        return self._tasks.get(task_id)

    def get_all_tasks(self) -> List[ScheduledTask]:
        """Get all scheduled tasks."""
        return list(self._tasks.values())

    def remove_task(self, task_id: str) -> bool:
        """Remove a task from the scheduler."""
        if task_id in self._tasks:
            del self._tasks[task_id]
            self.logger.debug(f"Removed task: {task_id}")
            return True
        return False

    def clear(self) -> None:
        """Clear all scheduled tasks."""
        self._tasks.clear()
        self.logger.debug("Cleared all tasks")
