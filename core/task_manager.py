"""
HAZARUS Task Manager
Manages concurrent task execution and resource allocation.
"""

from typing import Dict, Any, Optional, List
import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, UTC
import copy


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class Task:
    """A managed task."""
    task_id: str
    name: str
    func: callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Any = None
    error: Optional[str] = None
    _task: Optional[asyncio.Task] = None
    _paused_at: Optional[datetime] = None
    _resumed_at: Optional[datetime] = None
    _checkpoint: Optional[Dict[str, Any]] = None


class TaskManager:
    """
    Manages concurrent task execution with resource limits.
    """

    def __init__(self, event_bus, max_concurrent: int = 10):
        self.event_bus = event_bus
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger("hazarus.task_manager")

        self._tasks: Dict[str, Task] = {}
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running = False

    async def create_task(
        self,
        task_id: str,
        name: str,
        func: callable,
        *args,
        **kwargs
    ) -> Task:
        """
        Create and queue a task for execution.
        """
        if task_id in self._tasks:
            raise ValueError(f"Task {task_id} already exists")

        task = Task(task_id=task_id, name=name, func=func, args=args, kwargs=kwargs)
        self._tasks[task_id] = task

        # Start execution
        task._task = asyncio.create_task(self._execute_task(task))

        self.logger.debug(f"Created task: {task_id}")
        return task

    async def _execute_task(self, task: Task) -> None:
        """Execute a task with semaphore control."""
        async with self._semaphore:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.now(UTC)

            await self.event_bus.emit("task_start", {
                "task_id": task.task_id,
                "name": task.name
            })

            try:
                result = await task.func(*task.args, **task.kwargs)
                task.result = result
                task.status = TaskStatus.COMPLETED
                task.completed_at = datetime.now(UTC)

                await self.event_bus.emit("task_complete", {
                    "task_id": task.task_id,
                    "name": task.name,
                    "result": str(result)
                })

            except asyncio.CancelledError:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.now(UTC)
                self.logger.debug(f"Task cancelled: {task.task_id}")

                await self.event_bus.emit("task_cancelled", {
                    "task_id": task.task_id,
                    "name": task.name
                })

            except Exception as e:
                task.error = str(e)
                task.status = TaskStatus.FAILED
                task.completed_at = datetime.now(UTC)
                self.logger.error(f"Task {task.task_id} failed: {e}")

                await self.event_bus.emit("task_failed", {
                    "task_id": task.task_id,
                    "name": task.name,
                    "error": str(e)
                })

    async def wait_for_task(self, task_id: str, timeout: Optional[float] = None) -> Any:
        """Wait for a task to complete and return its result."""
        task = self.get_task(task_id)
        if not task:
            raise ValueError(f"Task {task_id} not found")

        if task._task:
            try:
                await asyncio.wait_for(task._task, timeout=timeout)
            except asyncio.TimeoutError:
                self.logger.warning(f"Task {task_id} timed out")
                raise

        if task.status == TaskStatus.FAILED:
            raise RuntimeError(task.error)
        elif task.status == TaskStatus.CANCELLED:
            raise RuntimeError(f"Task {task_id} was cancelled")

        return task.result

    async def wait_for_all(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """Wait for all tasks to complete."""
        tasks = [t._task for t in self._tasks.values() if t._task and t.status == TaskStatus.RUNNING]

        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=timeout)
            except asyncio.TimeoutError:
                self.logger.warning("Task group timed out")

        return {t.task_id: t.result for t in self._tasks.values() if t.status == TaskStatus.COMPLETED}

    def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task."""
        task = self.get_task(task_id)
        if not task or not task._task:
            return False

        if task.status in [TaskStatus.PENDING, TaskStatus.RUNNING]:
            task._task.cancel()
            return True

        return False

    async def cancel_all(self) -> int:
        """Cancel all running tasks."""
        cancelled = 0
        for task_id in list(self._tasks.keys()):
            if self.cancel_task(task_id):
                cancelled += 1

        return cancelled

    async def pause_all(self) -> None:
        """Pause all running tasks."""
        paused_count = 0
        for task in self.get_running_tasks():
            try:
                # Save task state for resumption
                task._paused_at = datetime.now(UTC)
                task._checkpoint = {
                    'task_id': task.task_id,
                    'name': task.name,
                    'args': task.args,
                    'kwargs': task.kwargs,
                    'status_before_pause': task.status.value
                }
                
                # Cancel the task (can be resumed by recreating)
                if task._task and not task._task.done():
                    task._task.cancel()
                    task.status = TaskStatus.PAUSED
                    paused_count += 1
                    self.logger.info(f"Paused task: {task.task_id}")
                    
            except Exception as e:
                self.logger.error(f"Failed to pause task {task.task_id}: {e}")
        
        self.logger.info(f"Paused {paused_count} tasks")

    async def resume_all(self) -> None:
        """Resume all paused tasks."""
        resumed_count = 0
        for task in list(self._tasks.values()):
            if task.status == TaskStatus.PAUSED and task._checkpoint:
                try:
                    # Restore task from checkpoint
                    checkpoint = task._checkpoint
                    task._resumed_at = datetime.now(UTC)
                    
                    # Recreate the task with original parameters
                    new_task = Task(
                        task_id=task.task_id,
                        name=checkpoint['name'],
                        func=task.func,
                        args=checkpoint['args'],
                        kwargs=checkpoint['kwargs'],
                        status=TaskStatus.PENDING
                    )
                    
                    # Replace old task with new one
                    self._tasks[task.task_id] = new_task
                    new_task._task = asyncio.create_task(self._execute_task(new_task))
                    
                    resumed_count += 1
                    self.logger.info(f"Resumed task: {task.task_id}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to resume task {task.task_id}: {e}")
        
        self.logger.info(f"Resumed {resumed_count} tasks")

    async def stop_all(self) -> None:
        """Stop all tasks gracefully."""
        await self.cancel_all()

    async def kill_all(self) -> None:
        """Kill all tasks immediately."""
        for task in self._tasks.values():
            if task._task:
                task._task.cancel()

        self.logger.warning("Killed all tasks")

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        return self._tasks.get(task_id)

    def get_all_tasks(self) -> List[Task]:
        """Get all tasks."""
        return list(self._tasks.values())

    def get_running_tasks(self) -> List[Task]:
        """Get all running tasks."""
        return [t for t in self._tasks.values() if t.status == TaskStatus.RUNNING]

    def get_pending_tasks(self) -> List[Task]:
        """Get all pending tasks."""
        return [t for t in self._tasks.values() if t.status == TaskStatus.PENDING]

    def get_completed_tasks(self) -> List[Task]:
        """Get all completed tasks."""
        return [t for t in self._tasks.values() if t.status == TaskStatus.COMPLETED]

    def remove_task(self, task_id: str) -> bool:
        """Remove a task from the manager."""
        if task_id in self._tasks:
            del self._tasks[task_id]
            self.logger.debug(f"Removed task: {task_id}")
            return True
        return False

    def clear(self) -> None:
        """Clear all tasks."""
        self._tasks.clear()
        self.logger.debug("Cleared all tasks")

    def get_stats(self) -> Dict[str, int]:
        """Get task statistics."""
        return {
            "total": len(self._tasks),
            "pending": len(self.get_pending_tasks()),
            "running": len(self.get_running_tasks()),
            "completed": len(self.get_completed_tasks()),
            "failed": len([t for t in self._tasks.values() if t.status == TaskStatus.FAILED]),
            "cancelled": len([t for t in self._tasks.values() if t.status == TaskStatus.CANCELLED])
        }
