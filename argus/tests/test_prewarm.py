"""Tests for argus.core.prewarm — ImagePrewarmer."""

import threading
import time

import pytest

from argus.core.prewarm import ImagePrewarmer, NOT_WARMED


class TestImagePrewarmerBasics:
    """Submission, dedup, and the wait_for contract."""

    def test_wait_for_unknown_image_returns_sentinel(self):
        prewarmer = ImagePrewarmer(pull_fn=lambda img: True)

        # Never called start() — no images registered.
        assert prewarmer.wait_for("img:never-warmed") is NOT_WARMED

    def test_start_then_wait_returns_true_on_success(self):
        prewarmer = ImagePrewarmer(pull_fn=lambda img: True)

        prewarmer.start(["img:a"])
        try:
            assert prewarmer.wait_for("img:a") is True
        finally:
            prewarmer.shutdown(wait=True)

    def test_start_then_wait_returns_false_on_pull_failure(self):
        prewarmer = ImagePrewarmer(pull_fn=lambda img: False)

        prewarmer.start(["img:a"])
        try:
            assert prewarmer.wait_for("img:a") is False
        finally:
            prewarmer.shutdown(wait=True)

    def test_start_dedups_repeated_images(self):
        """Two scanners that share an image -> one pull."""
        call_count = {"n": 0}
        lock = threading.Lock()

        def pull(image):
            with lock:
                call_count["n"] += 1
            return True

        prewarmer = ImagePrewarmer(pull_fn=pull)

        # Same image submitted multiple ways: in the same start() call,
        # and across two separate calls. Only one pull should fire.
        prewarmer.start(["img:shared", "img:shared", "img:other"])
        prewarmer.start(["img:shared", "img:other"])

        # Wait for both to finish so the pull count is stable.
        assert prewarmer.wait_for("img:shared") is True
        assert prewarmer.wait_for("img:other") is True
        prewarmer.shutdown(wait=True)

        assert call_count["n"] == 2  # img:shared + img:other, not 4

    def test_start_filters_empty_images(self):
        """Empty strings (scanners without container_image) are skipped."""
        called_with = []

        def pull(image):
            called_with.append(image)
            return True

        prewarmer = ImagePrewarmer(pull_fn=pull)

        # Empty + valid + empty — only the valid one should run.
        prewarmer.start(["", "img:real", ""])
        prewarmer.wait_for("img:real")
        prewarmer.shutdown(wait=True)

        assert called_with == ["img:real"]
        # Empty string never gets registered, so a wait_for returns the
        # sentinel — engine must fall back to inline pull.
        prewarmer2 = ImagePrewarmer(pull_fn=lambda img: True)
        assert prewarmer2.wait_for("") is NOT_WARMED

    def test_pull_exception_isolated_as_failure(self):
        """A raising pull_fn doesn't crash the prewarmer — it's logged
        and treated as a failed warm so the engine falls back."""
        def pull(image):
            raise RuntimeError("docker daemon down")

        prewarmer = ImagePrewarmer(pull_fn=pull)

        prewarmer.start(["img:broken"])
        try:
            assert prewarmer.wait_for("img:broken") is False
        finally:
            prewarmer.shutdown(wait=True)


class TestImagePrewarmerConcurrency:
    """The thread pool and worker cap behaviour."""

    def test_max_workers_caps_concurrent_pulls(self):
        """A pool sized 2 should never have 3 in-flight pulls at once."""
        in_flight = {"n": 0, "max": 0}
        lock = threading.Lock()
        gate = threading.Event()

        def pull(image):
            with lock:
                in_flight["n"] += 1
                in_flight["max"] = max(in_flight["max"], in_flight["n"])
            # Hold each worker until the test releases the gate, so the
            # pool actually has time to pile up.
            gate.wait(timeout=2.0)
            with lock:
                in_flight["n"] -= 1
            return True

        prewarmer = ImagePrewarmer(pull_fn=pull, max_workers=2)
        prewarmer.start([f"img:{i}" for i in range(5)])

        # Give the pool a beat to spin up workers and hit the gate.
        time.sleep(0.1)
        with lock:
            observed_max = in_flight["max"]
        gate.set()

        # Drain everything before the assertion so the test doesn't
        # leak threads on failure.
        for i in range(5):
            prewarmer.wait_for(f"img:{i}")
        prewarmer.shutdown(wait=True)

        assert observed_max <= 2, (
            f"max_workers=2 but observed {observed_max} concurrent pulls"
        )

    def test_zero_workers_clamped_to_one(self):
        """A misconfigured 0 doesn't deadlock — clamps to 1."""
        prewarmer = ImagePrewarmer(pull_fn=lambda img: True, max_workers=0)
        prewarmer.start(["img:a"])
        try:
            assert prewarmer.wait_for("img:a") is True
        finally:
            prewarmer.shutdown(wait=True)


class TestImagePrewarmerShutdown:
    """Shutdown and cancellation semantics."""

    def test_shutdown_after_complete_is_safe(self):
        """Calling shutdown twice or after a pull's done is a no-op."""
        prewarmer = ImagePrewarmer(pull_fn=lambda img: True)

        prewarmer.start(["img:a"])
        prewarmer.wait_for("img:a")
        prewarmer.shutdown(wait=True)
        prewarmer.shutdown(wait=True)  # idempotent

    def test_start_after_shutdown_is_noop(self):
        prewarmer = ImagePrewarmer(pull_fn=lambda img: True)
        prewarmer.shutdown(wait=True)

        prewarmer.start(["img:late"])
        # Nothing was submitted post-shutdown, so this is unknown.
        assert prewarmer.wait_for("img:late") is NOT_WARMED

    def test_shutdown_cancel_pending_pulls(self):
        """``shutdown(wait=False)`` cancels pulls that haven't started."""
        started = {"count": 0}
        lock = threading.Lock()
        gate = threading.Event()

        def pull(image):
            with lock:
                started["count"] += 1
            gate.wait(timeout=2.0)
            return True

        # 1 worker, 5 jobs — only 1 actually starts; the other 4 are
        # queued and should be cancelled by shutdown(wait=False).
        prewarmer = ImagePrewarmer(pull_fn=pull, max_workers=1)
        prewarmer.start([f"img:{i}" for i in range(5)])

        # Wait for the first job to enter pull(), then shut down.
        for _ in range(50):
            with lock:
                if started["count"] >= 1:
                    break
            time.sleep(0.02)

        prewarmer.shutdown(wait=False)
        gate.set()  # let the in-flight one finish

        # Give the in-flight worker a moment to drain.
        time.sleep(0.1)
        with lock:
            total_started = started["count"]
        # We should not have started all 5 — at least 1 was cancelled.
        assert total_started < 5


class TestPullPolicyIntegration:
    """Pull-policy semantics live in the engine, not the orchestrator,
    but the prewarmer needs to be no-op friendly so the engine can opt
    out for ``pull_policy=never`` without special-casing every call site.
    """

    def test_empty_start_is_noop(self):
        prewarmer = ImagePrewarmer(pull_fn=lambda img: True)
        prewarmer.start([])  # nothing submitted
        prewarmer.shutdown(wait=True)

    def test_wait_for_with_timeout_returns_false_on_hang(self):
        """A pull that hangs past the timeout is reported as failed warm
        so the engine doesn't block the scan thread waiting for it."""
        gate = threading.Event()

        def pull(image):
            gate.wait(timeout=2.0)
            return True

        prewarmer = ImagePrewarmer(pull_fn=pull)
        prewarmer.start(["img:slow"])
        try:
            # 50ms timeout; pull holds the gate for up to 2s. The
            # wait_for should return False, not block.
            result = prewarmer.wait_for("img:slow", timeout=0.05)
            assert result is False
        finally:
            gate.set()
            prewarmer.shutdown(wait=True)
