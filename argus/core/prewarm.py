"""Image pre-warm orchestrator.

Pre-fetches container images in the background while the engine
prepares jobs, so a sequential scan of N scanners with N distinct
images overlaps pull-time with scan-time instead of running them
serially. Parallel scans see the same benefit indirectly: scanners
whose images are already cached (by pre-warm or a prior run) start
scanning immediately instead of contending for registry bandwidth.

Design properties (matches the roadmap acceptance criteria):

- **Best-effort.** Pre-warm failures are swallowed here; the engine's
  inline ``_pull_image`` is the source of truth for "is the image
  available". A pre-warm hit is an optimisation, not a correctness
  requirement.
- **Dedup.** Two scanners that share an image (e.g. ``trivy-iac`` and
  the container scanner both use ``aquasec/trivy``) trigger one pull,
  not two.
- **Concurrency cap.** Bounded thread pool keeps registry-side fan-out
  reasonable — 20 scanners pulling 20 images at once is what we're
  actively trying to avoid.
- **Cancellable.** ``shutdown(wait=False)`` aborts pending pulls and
  detaches in-flight ones so a Ctrl+C in the engine doesn't strand
  zombie threads.
- **Silent on cached.** ``pull_policy=if-not-present`` paths skip the
  warm pull when the image is already local, so the happy path stays
  noiseless.
- **Honors pull_policy.** ``never`` makes pre-warm a no-op (would be
  wasted work — the engine refuses to pull anyway). ``always`` and
  ``if-not-present`` both feed through to ``_pull_image``.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from typing import Callable

logger = logging.getLogger("argus")


# Sentinel returned when the engine asks for an image we never warmed.
# Distinct from a failed warm so callers can fall through to inline pull
# without ambiguity.
_NOT_WARMED = object()


class ImagePrewarmer:
    """Orchestrate background image pulls keyed by image reference.

    The class is intentionally tiny: it owns a thread pool, a futures
    map, and a lock. The actual pull is done by a callable injected by
    the caller (the engine), so this module stays decoupled from
    ``subprocess`` and the runtime detection logic.
    """

    def __init__(
        self,
        pull_fn: Callable[[str], bool],
        max_workers: int = 4,
    ) -> None:
        """Build a prewarmer.

        Args:
            pull_fn: callable that takes an image reference and returns
                True on success, False on failure. The engine passes
                its own ``_pull_image`` here; tests pass a mock.
            max_workers: thread pool size. Defaults to 4 — empirically
                a registry-friendly fan-out that still lets a 5-scanner
                run finish prewarming before the first scanner is done.
        """
        # Clamp to a sensible floor so a misconfigured "0" doesn't
        # deadlock or fall back to ThreadPoolExecutor's default cpu_count.
        self._max_workers = max(1, int(max_workers))
        self._pull_fn = pull_fn
        self._lock = threading.Lock()
        self._futures: dict[str, concurrent.futures.Future] = {}
        self._pool: concurrent.futures.ThreadPoolExecutor | None = None
        self._closed = False

    def start(self, images: list[str]) -> None:
        """Submit pulls for the given image list, deduplicated.

        Empty strings and previously-submitted images are filtered out
        so callers can pass the raw scanner list without pre-processing.
        Idempotent: calling ``start([img])`` twice for the same image
        only spawns one pull.
        """
        # Dedup + drop empties. Preserve insertion order so logs are
        # deterministic in tests.
        unique: list[str] = []
        seen: set[str] = set()
        for image in images:
            if not image or image in seen:
                continue
            seen.add(image)
            unique.append(image)

        if not unique:
            logger.debug("Pre-warm: no images to pull")
            return

        with self._lock:
            if self._closed:
                logger.debug("Pre-warm: orchestrator closed — skipping start()")
                return

            if self._pool is None:
                self._pool = concurrent.futures.ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="argus-prewarm",
                )

            new = [img for img in unique if img not in self._futures]
            if not new:
                return

            logger.debug(
                "Pre-warm: submitting %d image(s) to pool (max_workers=%d): %s",
                len(new), self._max_workers, new,
            )
            for image in new:
                self._futures[image] = self._pool.submit(
                    self._safe_pull, image,
                )

    def wait_for(self, image: str, timeout: float | None = None) -> object:
        """Block until ``image`` finishes warming.

        Returns:
            ``True``  — pre-warm pulled the image successfully
            ``False`` — pre-warm tried and failed (engine should fall
                back to inline pull)
            ``_NOT_WARMED`` — we never submitted a pull for this image;
                caller should run its own pull.

        ``timeout`` is forwarded to ``Future.result``. On
        ``concurrent.futures.TimeoutError`` we treat the warm as
        failed-by-timeout and surface ``False`` so the caller falls
        back to inline pull rather than hanging.
        """
        with self._lock:
            future = self._futures.get(image)

        if future is None:
            return _NOT_WARMED

        try:
            return bool(future.result(timeout=timeout))
        except concurrent.futures.TimeoutError:
            logger.debug(
                "Pre-warm: %s did not finish within %ss — falling back to inline pull",
                image, timeout,
            )
            return False
        except Exception as exc:  # pragma: no cover — _safe_pull catches
            # Defensive — _safe_pull should already swallow these.
            logger.debug("Pre-warm: %s raised: %s", image, exc)
            return False

    def shutdown(self, wait: bool = False) -> None:
        """Stop the orchestrator. Cancels pending pulls if ``wait=False``.

        Safe to call from a signal handler / KeyboardInterrupt path:
        in-flight pulls finish on their own (the subprocess they ran
        is the one holding the network — no point in racing it), but
        no new pulls start.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            pool = self._pool
            self._pool = None
            futures = list(self._futures.values())

        if pool is None:
            return

        # cancel_futures is the right knob here: in-flight pulls keep
        # running (we can't kill the subprocess from another thread
        # cleanly), but pending ones never start. Available since 3.9.
        if not wait:
            for fut in futures:
                fut.cancel()

        pool.shutdown(wait=wait, cancel_futures=not wait)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _safe_pull(self, image: str) -> bool:
        """Run ``pull_fn(image)`` with bare-bones exception isolation.

        Pre-warm is best-effort by contract — anything raising here
        becomes a False return so ``wait_for`` can tell the engine to
        fall back to its inline pull. The full traceback lands at
        DEBUG so the happy path stays quiet but a developer chasing
        a regression can flip log level and see what blew up.
        """
        try:
            return bool(self._pull_fn(image))
        except Exception:  # noqa: BLE001 — pre-warm is best-effort
            logger.debug(
                "Pre-warm: pull function raised for %s", image, exc_info=True,
            )
            return False


__all__ = ["ImagePrewarmer", "NOT_WARMED"]

# Public alias for the not-warmed sentinel so callers can compare without
# reaching into the module's private state.
NOT_WARMED = _NOT_WARMED
