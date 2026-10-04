# bgtasks.py — ساخت تسک پس‌زمینه با نگه‌داشتن reference و لاگ خطا.
# asyncio فقط weak reference به تسک نگه می‌دارد؛ تسکی که کسی ارجاعش را نگه نداره
# ممکن است وسط اجرا garbage-collect شود و خطایش هم هیچ‌وقت دیده نمی‌شود.
import asyncio
import logging

logger = logging.getLogger("RVG-Gateway")
_tasks: set = set()


def _done(task: asyncio.Task):
    _tasks.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error(
            f"Background task {task.get_name()} failed: {type(exc).__name__}: {exc}",
            exc_info=exc,
        )


def spawn(coro, name: str | None = None) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    _tasks.add(task)
    task.add_done_callback(_done)
    return task
