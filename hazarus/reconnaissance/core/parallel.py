"""
HAZARUS Parallel Execution Engine
Parallel task execution with concurrency control and rate limiting.
"""

import asyncio
import logging
from typing import Callable, List, Any, Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime, UTC
import time


@dataclass
class TaskResult:
    """Result of a parallel task."""
    task_name: str
    success: bool
    result: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    started_at: datetime = None
    completed_at: datetime = None

    def __post_init__(self):
        if self.started_at is None:
            self.started_at = datetime.now(UTC)
        if self.completed_at is None:
            self.completed_at = datetime.now(UTC)


@dataclass
class ParallelStats:
    """Statistics for parallel execution."""
    total_tasks: int = 0
    successful_tasks: int = 0
    failed_tasks: int = 0
    total_duration: float = 0.0
    average_duration: float = 0.0
    errors: List[str] = field(default_factory=list)


class ParallelRecon:
    """Parallel execution engine for reconnaissance tasks."""

    def __init__(
        self,
        max_concurrent: int = 10,
        rate_limit: Optional[int] = None  # requests per second
    ):
        """
        Initialize parallel execution engine.

        Args:
            max_concurrent: Maximum number of concurrent tasks
            rate_limit: Maximum requests per second (None = no limit)
        """
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.logger = logging.getLogger("hazarus.parallel_recon")
        self.stats = ParallelStats()

    async def run_parallel_tasks(
        self,
        tasks: List[Callable],
        task_names: Optional[List[str]] = None
    ) -> List[TaskResult]:
        """
        Run multiple tasks in parallel.

        Args:
            tasks: List of async callable tasks
            task_names: Optional list of task names for tracking

        Returns:
            List of TaskResult objects
        """
        if task_names is None:
            task_names = [f"task_{i}" for i in range(len(tasks))]

        self.stats.total_tasks = len(tasks)
        self.logger.info(f"Running {len(tasks)} tasks in parallel (max: {self.max_concurrent})")

        # Create coroutine list
        coroutines = []
        for task, name in zip(tasks, task_names):
            coroutines.append(self._run_with_semaphore(task, name))

        # Run all tasks
        results = await asyncio.gather(*coroutines, return_exceptions=True)

        # Process results
        task_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                task_results.append(TaskResult(
                    task_name=task_names[i],
                    success=False,
                    error=str(result)
                ))
                self.stats.failed_tasks += 1
                self.stats.errors.append(f"{task_names[i]}: {str(result)}")
            else:
                task_results.append(result)
                if result.success:
                    self.stats.successful_tasks += 1
                else:
                    self.stats.failed_tasks += 1
                    self.stats.errors.append(f"{task_names[i]}: {result.error}")

        # Calculate statistics
        successful_durations = [r.duration for r in task_results if r.success]
        if successful_durations:
            self.stats.average_duration = sum(successful_durations) / len(successful_durations)
        self.stats.total_duration = sum(r.duration for r in task_results)

        self.logger.info(
            f"Parallel execution complete: "
            f"{self.stats.successful_tasks} succeeded, "
            f"{self.stats.failed_tasks} failed, "
            f"avg duration: {self.stats.average_duration:.2f}s"
        )

        return task_results

    async def _run_with_semaphore(
        self,
        task: Callable,
        task_name: str
    ) -> TaskResult:
        """Run task with semaphore and rate limiting."""
        result = TaskResult(task_name=task_name)
        start_time = time.time()

        try:
            # Acquire semaphore
            async with self.semaphore:
                # Apply rate limiting if configured
                if self.rate_limit:
                    await self._rate_limit_delay()

                # Execute task
                task_result = await task()
                result.success = True
                result.result = task_result

        except Exception as e:
            result.success = False
            result.error = str(e)
            self.logger.error(f"Task {task_name} failed: {e}")

        finally:
            result.duration = time.time() - start_time
            result.completed_at = datetime.now(UTC)

        return result

    async def _rate_limit_delay(self) -> None:
        """Calculate delay for rate limiting."""
        # Simple implementation: sleep to maintain rate
        if self.rate_limit:
            delay = 1.0 / self.rate_limit
            await asyncio.sleep(delay)

    async def run_with_semaphore(
        self,
        tasks: List[Callable],
        max_concurrent: int,
        task_names: Optional[List[str]] = None
    ) -> List[TaskResult]:
        """
        Run tasks with custom semaphore.

        Args:
            tasks: List of async callable tasks
            max_concurrent: Maximum concurrent tasks for this run
            task_names: Optional list of task names

        Returns:
            List of TaskResult objects
        """
        original_max = self.max_concurrent
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)

        try:
            return await self.run_parallel_tasks(tasks, task_names)
        finally:
            self.max_concurrent = original_max
            self.semaphore = asyncio.Semaphore(original_max)

    async def run_with_rate_limit(
        self,
        tasks: List[Callable],
        requests_per_second: int,
        task_names: Optional[List[str]] = None
    ) -> List[TaskResult]:
        """
        Run tasks with rate limiting.

        Args:
            tasks: List of async callable tasks
            requests_per_second: Maximum requests per second
            task_names: Optional list of task names

        Returns:
            List of TaskResult objects
        """
        original_rate = self.rate_limit
        self.rate_limit = requests_per_second

        try:
            return await self.run_parallel_tasks(tasks, task_names)
        finally:
            self.rate_limit = original_rate

    def get_stats(self) -> ParallelStats:
        """Get execution statistics."""
        return self.stats

    def reset_stats(self) -> None:
        """Reset statistics."""
        self.stats = ParallelStats()


class PriorityTask:
    """Task with priority for execution."""

    def __init__(
        self,
        task: Callable,
        priority: int,  # Lower = higher priority
        name: str = ""
    ):
        self.task = task
        self.priority = priority
        self.name = name


class PriorityParallelRecon(ParallelRecon):
    """Parallel execution with task prioritization."""

    async def run_priority_tasks(
        self,
        tasks: List[PriorityTask]
    ) -> List[TaskResult]:
        """
        Run tasks in priority order (higher priority first).

        Args:
            tasks: List of PriorityTask objects

        Returns:
            List of TaskResult objects
        """
        # Sort by priority
        sorted_tasks = sorted(tasks, key=lambda t: t.priority)

        # Extract callables and names
        callables = [t.task for t in sorted_tasks]
        names = [t.name for t in sorted_tasks]

        self.logger.info(
            f"Running {len(tasks)} priority tasks "
            f"(highest priority: {sorted_tasks[0].priority})"
        )

        return await self.run_parallel_tasks(callables, names)
