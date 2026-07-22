"""
Vision-M Scheduler
==================
Cron-like recurring job scheduler with:
  - JSON schedule storage for durability across restarts
  - JobQueue integration (fires create JobContracts and enqueue)
  - APScheduler backend with heapq+threading fallback
  - Frequency parsing: Ns (seconds), Nm (minutes), Nh (hours), daily (24h)
"""

from __future__ import annotations

import os
import json
import re
import threading
import heapq
import uuid
import time
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# ── fcntl file locking (cross-process safety) ─────────────────────
try:
    import fcntl
    HAS_FCNTL = True
except ImportError:
    HAS_FCNTL = False

logger = logging.getLogger(__name__)

# ── Backend selection ─────────────────────────────────────────────
HAS_APSCHEDULER = False
FALLBACK_MODE = True

_BackgroundScheduler: Any = None   # type: ignore[no-redef]
_IntervalTrigger: Any = None

try:
    from apscheduler.schedulers.background import BackgroundScheduler as _BGS
    from apscheduler.triggers.interval import IntervalTrigger as _IT
    _BackgroundScheduler = _BGS
    _IntervalTrigger = _IT
    HAS_APSCHEDULER = True
    FALLBACK_MODE = False
    logger.info("Vision Scheduler: using APScheduler backend")
except ImportError:
    logger.info("Vision Scheduler: APScheduler not available, using heapq fallback")


# ═══════════════════════════════════════════════════════════════════
# Frequency parsing
# ═══════════════════════════════════════════════════════════════════

_FREQ_PATTERN = re.compile(
    r"^(?P<value>\d+)\s*(?P<unit>[smh]|sec|secs|second|seconds|min|mins|minute|minutes|hr|hrs|hour|hours)$",
    re.IGNORECASE,
)


def parse_frequency(freq: str) -> int:
    """Parse a frequency string into total seconds.

    Supported formats:
        - "Ns" / "Nsec" / "Nseconds"  → N seconds
        - "Nm" / "Nmin" / "Nminutes"  → N * 60 seconds
        - "Nh" / "Nhr" / "Nhours"      → N * 3600 seconds
        - "daily" / "day"              → 86400 seconds (24h)

    Returns:
        Total seconds as an int.

    Raises:
        ValueError: If the frequency string cannot be parsed.
    """
    freq = freq.strip().lower()

    if freq in ("daily", "day"):
        return 86400

    m = _FREQ_PATTERN.match(freq)
    if not m:
        raise ValueError(
            f"Unrecognised frequency: '{freq}'. "
            f"Expected: Ns, Nm, Nh, or daily."
        )

    value = int(m.group("value"))
    unit = m.group("unit")[0]  # first char: s, m, h

    if unit == "s":
        return value
    elif unit == "m":
        return value * 60
    elif unit == "h":
        return value * 3600

    raise ValueError(f"Unrecognised unit in frequency: '{freq}'")


# ═══════════════════════════════════════════════════════════════════
# JSON schedule store
# ═══════════════════════════════════════════════════════════════════

class ScheduleStore:
    """Persists schedule configurations to a JSON file."""

    def __init__(self, store_path: str):
        self.store_path = store_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(store_path), exist_ok=True)
        if not os.path.exists(store_path):
            self._write({})

    def load_all(self) -> Dict[str, dict]:
        """Load all schedules from JSON."""
        try:
            with open(self.store_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save(self, schedule_id: str, config: dict):
        """Persist a single schedule."""
        if HAS_FCNTL:
            lock_fd = self._acquire_store_lock()
            try:
                data = self._load_unlocked()
                data[schedule_id] = config
                self._write(data)
            finally:
                self._release_store_lock(lock_fd)
        else:
            with self._lock:
                data = self._load_unlocked()
                data[schedule_id] = config
                self._write(data)

    def delete(self, schedule_id: str) -> bool:
        """Remove a schedule. Returns True if it existed."""
        if HAS_FCNTL:
            lock_fd = self._acquire_store_lock()
            try:
                data = self._load_unlocked()
                if schedule_id in data:
                    del data[schedule_id]
                    self._write(data)
                    return True
                return False
            finally:
                self._release_store_lock(lock_fd)
        else:
            with self._lock:
                data = self._load_unlocked()
                if schedule_id in data:
                    del data[schedule_id]
                    self._write(data)
                    return True
                return False

    def _load_unlocked(self) -> Dict[str, dict]:
        """Load all schedules without extra locking (caller holds file lock)."""
        try:
            with open(self.store_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _acquire_store_lock(self):
        """Acquire an exclusive file lock on a dedicated lock-file.

        Returns an open file descriptor (or None on platforms without fcntl).
        The caller must pass this to _release_store_lock().
        """
        if not HAS_FCNTL:
            return None
        lock_path = self.store_path + ".lock"
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _release_store_lock(self, fd):
        """Release a file lock acquired by _acquire_store_lock()."""
        if fd is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _write(self, data: dict):
        tmp = self.store_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, self.store_path)


# ═══════════════════════════════════════════════════════════════════
# heapq-based fallback scheduler
# ═══════════════════════════════════════════════════════════════════

class _HeapScheduler:
    """Lightweight heapq+threading scheduler used when APScheduler is absent.

    Internals:
        - A min-heap of (next_fire_utc_ts, schedule_id, interval_seconds)
        - A background thread that sleep-until-next / condition-waits
        - Each fire triggers a user-supplied callback.
    """

    def __init__(self):
        self._heap: List[Tuple[float, str, int, dict]] = []  # (next_ts, sched_id, interval, config)
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._callbacks: Dict[str, Tuple[Callable, tuple, dict]] = {}  # sched_id → (fn, args, kwargs)

    def add_job(
        self,
        fn: Callable,
        trigger: str = "interval",
        seconds: int = 60,
        args: Optional[tuple] = None,
        kwargs: Optional[dict] = None,
        id: Optional[str] = None,
        name: Optional[str] = None,
    ) -> str:
        """Add a recurring job. Returns the schedule id."""
        sched_id = id or str(uuid.uuid4())
        next_ts = time.time() + seconds

        with self._lock:
            config = {
                "id": sched_id,
                "name": name or "",
                "seconds": seconds,
                "next_fire_ts": next_ts,
            }
            heapq.heappush(self._heap, (next_ts, sched_id, seconds, config))
            self._callbacks[sched_id] = (fn, args or (), kwargs or {})
            self._cv.notify()

        logger.debug("HeapScheduler: added job %s (interval=%ds, next_fire=%.1f)", sched_id, seconds, next_ts)
        return sched_id

    def remove_job(self, sched_id: str) -> bool:
        """Remove a scheduled job. Returns True if found."""
        with self._lock:
            if sched_id in self._callbacks:
                del self._callbacks[sched_id]
            # Rebuild heap without the removed id
            self._heap = [
                item for item in self._heap if item[1] != sched_id
            ]
            heapq.heapify(self._heap)
            self._cv.notify()
            return True
        return False

    def start(self):
        """Start the background scheduler thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="vision-scheduler-heap")
        self._thread.start()
        logger.info("HeapScheduler: started")

    def stop(self):
        """Stop the background scheduler thread gracefully."""
        self._running = False
        with self._lock:
            self._cv.notify()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)
        logger.info("HeapScheduler: stopped")

    def shutdown(self, wait: bool = False):
        """Compatibility alias for APScheduler's shutdown()."""
        self.stop()

    def _loop(self):
        """Main scheduler loop: pop from heap, execute callback, re-schedule."""
        while self._running:
            with self._lock:
                if not self._heap:
                    # Nothing scheduled — wait until notified or stopped
                    self._cv.wait(timeout=1.0)
                    continue

                next_ts, sched_id, interval, config = self._heap[0]
                now = time.time()
                wait = next_ts - now

                if wait > 0:
                    # Not yet — wait with timeout
                    self._cv.wait(timeout=min(wait, 1.0))
                    continue

                # Pop and fire
                heapq.heappop(self._heap)

                callback_entry = self._callbacks.get(sched_id)
                if callback_entry is None:
                    continue  # Was removed while waiting

            # Fire outside the lock
            fn, args, kwargs = callback_entry
            try:
                fn(*args, **kwargs)
            except Exception:
                logger.exception("HeapScheduler: callback for %s raised", sched_id)

            # Re-schedule
            with self._lock:
                if sched_id in self._callbacks:
                    new_next = time.time() + interval
                    config["next_fire_ts"] = new_next
                    heapq.heappush(self._heap, (new_next, sched_id, interval, config))
                    logger.debug("HeapScheduler: re-queued %s (next at %.1f)", sched_id, new_next)


# ═══════════════════════════════════════════════════════════════════
# VisionScheduler — main public API
# ═══════════════════════════════════════════════════════════════════

class VisionScheduler:
    """Recurring job scheduler with JobQueue integration.

    Usage:
        from layer1_orchestration.scheduler import VisionScheduler
        from layer1_orchestration.execution.job_queue import JobQueue
        from layer1_orchestration.execution.job_store import JobStore
        from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager

        store = JobStore()
        lifecycle = JobLifecycleManager()
        queue = JobQueue(store, lifecycle)

        sched = VisionScheduler(job_queue=queue)
        sid = sched.add_schedule("example.com", "30s", "security_scan")
        sched.start_scheduler()
        ...
        sched.stop_scheduler()
    """

    STORE_PATH = os.path.join(os.path.dirname(__file__), "schedules.json")

    def __init__(self, job_queue=None, store_path: Optional[str] = None):
        """
        Args:
            job_queue: A JobQueue instance. If None, one will be lazily created
                       on first use (with default store/lifecycle).
            store_path: Path to the schedules JSON file.
        """
        self._job_queue = job_queue
        self._store = ScheduleStore(store_path or self.STORE_PATH)

        if HAS_APSCHEDULER:
            self._backend = _BackgroundScheduler(daemon=True)
        else:
            self._backend = _HeapScheduler()

        self._apscheduler_jobs: Dict[str, Any] = {}
        self._running = False
        self._lock = threading.Lock()

    # ── Lazy JobQueue ──────────────────────────────────────────

    def _get_queue(self):
        """Return the JobQueue, creating a default one if needed."""
        if self._job_queue is None:
            from layer1_orchestration.execution.job_store import JobStore
            from layer1_orchestration.execution.job_lifecycle import JobLifecycleManager
            from layer1_orchestration.execution.job_queue import JobQueue

            self._job_queue = JobQueue(
                store=JobStore(),
                lifecycle=JobLifecycleManager(),
            )
        return self._job_queue

    # ── Public API ─────────────────────────────────────────────

    def add_schedule(
        self,
        target: str,
        frequency: str,
        engine: str,
        **kwargs,
    ) -> str:
        """Register a recurring schedule.

        Args:
            target: Scan target, e.g. "example.com".
            frequency: How often to fire, e.g. "30s", "5m", "2h", "daily".
            engine: Engine name, e.g. "security_scan", "scraping_scan", "mining_scan".
            **kwargs: Additional parameters passed through to the JobContract
                      (e.g. requested_action, tenant_id, etc.).

        Returns:
            A unique schedule ID string.
        """
        interval_seconds = parse_frequency(frequency)
        sched_id = str(uuid.uuid4())

        config = {
            "schedule_id": sched_id,
            "target": target,
            "frequency": frequency,
            "interval_seconds": interval_seconds,
            "engine": engine,
            "kwargs": kwargs,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        # Persist to JSON
        self._store.save(sched_id, config)

        # Schedule the callback
        def _fire():
            self._on_schedule_fire(sched_id)

        if HAS_APSCHEDULER:
            job = self._backend.add_job(
                _fire,
                trigger=_IntervalTrigger(seconds=interval_seconds),
                id=sched_id,
                name=f"{engine}:{target}",
                replace_existing=True,
            )
            self._apscheduler_jobs[sched_id] = job
        else:
            self._backend.add_job(
                _fire,
                seconds=interval_seconds,
                id=sched_id,
                name=f"{engine}:{target}",
            )

        logger.info(
            "VisionScheduler: added schedule %s — engine=%s target=%s freq=%s (interval=%ds)",
            sched_id, engine, target, frequency, interval_seconds,
        )
        return sched_id

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule by ID. Returns True if it existed."""
        removed_store = self._store.delete(schedule_id)

        if HAS_APSCHEDULER:
            job = self._apscheduler_jobs.pop(schedule_id, None)
            if job is not None:
                try:
                    job.remove()
                except Exception:
                    # Job may already be gone (e.g. scheduler shut down)
                    logger.debug("VisionScheduler: job %s already removed from backend", schedule_id)
        else:
            self._backend.remove_job(schedule_id)

        if removed_store:
            logger.info("VisionScheduler: removed schedule %s", schedule_id)
        return removed_store

    def list_schedules(self) -> List[dict]:
        """Return a list of all stored schedule configurations."""
        data = self._store.load_all()
        return list(data.values())

    def start_scheduler(self):
        """Start the scheduler (background thread)."""
        if self._running:
            logger.warning("VisionScheduler: already running")
            return

        # Restore previously persisted schedules
        self._restore_schedules()

        self._backend.start()
        self._running = True
        logger.info("VisionScheduler: started (%s backend)",
                     "APScheduler" if HAS_APSCHEDULER else "heapq")

    def stop_scheduler(self):
        """Stop the scheduler gracefully."""
        if not self._running:
            return

        self._backend.shutdown(wait=False)
        self._running = False
        logger.info("VisionScheduler: stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Internals ──────────────────────────────────────────────

    def _restore_schedules(self):
        """Re-register persisted schedules on start."""
        schedules = self._store.load_all()
        for sched_id, config in schedules.items():
            interval = config.get("interval_seconds", 60)
            sched_id_ref = sched_id  # capture for closure

            def _fire(sid=sched_id_ref):
                self._on_schedule_fire(sid)

            if HAS_APSCHEDULER:
                job = self._backend.add_job(
                    _fire,
                    trigger=_IntervalTrigger(seconds=interval),
                    id=sched_id,
                    name=f"{config.get('engine','')}:{config.get('target','')}",
                    replace_existing=True,
                )
                self._apscheduler_jobs[sched_id] = job
            else:
                self._backend.add_job(
                    _fire,
                    seconds=interval,
                    id=sched_id,
                    name=f"{config.get('engine','')}:{config.get('target','')}",
                )

            logger.debug("VisionScheduler: restored schedule %s", sched_id)

    def _on_schedule_fire(self, schedule_id: str):
        """Called when a schedule fires. Creates and enqueues a JobRecord."""
        schedules = self._store.load_all()
        config = schedules.get(schedule_id)
        if not config:
            logger.warning("VisionScheduler: schedule %s not found in store — skipping", schedule_id)
            return

        target = config["target"]
        engine = config["engine"]
        extra_kwargs = config.get("kwargs", {})

        logger.info("VisionScheduler: schedule %s fired — engine=%s target=%s",
                     schedule_id, engine, target)

        try:
            from layer1_orchestration.execution.job_contract import JobContract, JobRecord

            contract = JobContract(
                job_id=str(uuid.uuid4()),
                requested_action=extra_kwargs.get("requested_action", f"Scheduled {engine}"),
                action_type=engine,
                source_engine="vision_scheduler",
                target_engine=engine,
                target_asset=target,
                normalized_asset=target,
                idempotency_key=f"sched:{schedule_id}:{int(time.time())}",
                tenant_id=extra_kwargs.get("tenant_id", ""),
                **{k: v for k, v in extra_kwargs.items()
                   if k not in ("requested_action", "tenant_id")},
            )

            record = JobRecord(contract=contract)

            queue = self._get_queue()
            enqueued = queue.enqueue(record)

            logger.info(
                "VisionScheduler: enqueued job %s for schedule %s (engine=%s, target=%s)",
                enqueued.contract.job_id, schedule_id, engine, target,
            )
        except Exception:
            logger.exception("VisionScheduler: failed to enqueue job for schedule %s", schedule_id)
