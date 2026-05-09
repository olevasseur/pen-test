import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pentest_harness.adapters.cheddar.profile import get_profile
from pentest_harness.cli import main
from pentest_harness.core import artifacts
from pentest_harness.core.modules import EvidenceLevel, ModuleMetadata, ModuleResult, SafetyLevel
from pentest_harness.core.roe import RulesOfEngagement
from pentest_harness.core.scans import ScanModuleState, ScanPlan, heartbeat_path, load_scan_state, write_scan_state, write_scan_summary, ScanState, utc_now
from pentest_harness.core.targets import TargetProfile


class ScanTests(unittest.TestCase):
    def test_resolves_baseline_scan_plan(self):
        plan = get_profile().scan_plans()["baseline"]
        self.assertEqual(plan.module_ids, ("route-inventory", "security-map-drift", "checkout-exposure-summary", "webhook-negative"))
        self.assertEqual(plan.max_evidence_level, EvidenceLevel.NON_MUTATING_PROBE)

    def test_scan_runs_modules_in_order_and_downgrades_observe_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile(
                {
                    "static": FakeModule("static", (EvidenceLevel.OBSERVE_ONLY,), calls),
                    "probe": FakeModule("probe", (EvidenceLevel.NON_MUTATING_PROBE,), calls),
                },
                ("static", "probe"),
            )
            with _scan_test_context(tmp, profile):
                code = _run_main(
                    [
                        "scan",
                        "demo",
                        "baseline",
                        "--target",
                        "staging",
                        "--target-repo",
                        "/tmp/demo",
                        "--evidence-level",
                        "non_mutating_probe",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(calls, [("static", "observe_only"), ("probe", "non_mutating_probe")])
            state = _only_state("demo", tmp)
            self.assertEqual([item.module_id for item in state.completed], ["static", "probe"])

    def test_non_mutating_module_is_skipped_under_observe_only_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile({"probe": FakeModule("probe", (EvidenceLevel.NON_MUTATING_PROBE,), calls)}, ("probe",))
            with _scan_test_context(tmp, profile):
                code = _run_main(["scan", "demo", "baseline", "--target", "staging", "--target-repo", "/tmp/demo", "--evidence-level", "observe_only"])
            self.assertEqual(code, 0)
            self.assertEqual(calls, [])
            state = _only_state("demo", tmp)
            self.assertEqual([item.module_id for item in state.skipped], ["probe"])

    def test_resume_skips_completed_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile(
                {
                    "first": FakeModule("first", (EvidenceLevel.OBSERVE_ONLY,), calls),
                    "second": FakeModule("second", (EvidenceLevel.OBSERVE_ONLY,), calls),
                },
                ("first", "second"),
            )
            with _scan_test_context(tmp, profile):
                state = ScanState(
                    scan_id="baseline-existing",
                    project="demo",
                    plan_id="baseline",
                    target="staging",
                    target_repo="/tmp/demo",
                    requested_evidence_level="observe_only",
                    started_at=utc_now(),
                )
                state.completed.append(ScanModuleState(module_id="first", status="completed"))
                write_scan_state(state)
                code = _run_main(["scan", "demo", "baseline", "--resume", "baseline-existing", "--target-repo", "/tmp/demo"])
            self.assertEqual(code, 0)
            self.assertEqual(calls, [("second", "observe_only")])

    def test_scan_state_records_completed_failed_and_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile(
                {
                    "ok": FakeModule("ok", (EvidenceLevel.OBSERVE_ONLY,), calls),
                    "fail": FakeModule("fail", (EvidenceLevel.OBSERVE_ONLY,), calls, fail=True),
                    "skip": FakeModule("skip", (EvidenceLevel.NON_MUTATING_PROBE,), calls),
                },
                ("ok", "fail", "skip"),
            )
            with _scan_test_context(tmp, profile):
                code = _run_main(["scan", "demo", "baseline", "--target", "staging", "--target-repo", "/tmp/demo", "--evidence-level", "observe_only"])
            self.assertEqual(code, 0)
            state = _only_state("demo", tmp)
            self.assertEqual([item.module_id for item in state.completed], ["ok"])
            self.assertEqual([item.module_id for item in state.failed], ["fail"])
            self.assertEqual([item.module_id for item in state.skipped], ["skip"])

    def test_production_gates_are_not_bypassed_by_scan_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile({"probe": FakeModule("probe", (EvidenceLevel.NON_MUTATING_PROBE,), calls)}, ("probe",))
            with _scan_test_context(tmp, profile):
                code = _run_main(
                    [
                        "scan",
                        "demo",
                        "baseline",
                        "--target",
                        "production",
                        "--target-repo",
                        "/tmp/demo",
                        "--evidence-level",
                        "non_mutating_probe",
                    ]
                )
            self.assertEqual(code, 2)
            self.assertEqual(calls, [])

    def test_scan_list_with_no_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _scan_test_context(tmp, FakeProfile({}, ())):
                code, stdout, _stderr = _run_main_capture(["scan", "list", "demo"])
        self.assertEqual(code, 0)
        self.assertIn("No scans found", stdout)

    def test_scan_list_with_one_completed_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _scan_test_context(tmp, FakeProfile({}, ())):
                state = ScanState(
                    scan_id="scan-1",
                    project="demo",
                    plan_id="baseline",
                    target="staging",
                    target_repo="/tmp/demo",
                    requested_evidence_level="observe_only",
                    started_at=utc_now(),
                    status="finished",
                    finished_at=utc_now(),
                )
                state.completed.append(ScanModuleState(module_id="one", status="completed"))
                write_scan_state(state)
                write_scan_summary(state)
                code, stdout, _stderr = _run_main_capture(["scan", "list", "demo"])
        self.assertEqual(code, 0)
        self.assertIn("scan-1", stdout)
        self.assertIn("completed=1", stdout)
        self.assertIn("summary=", stdout)

    def test_scan_status_for_existing_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _scan_test_context(tmp, FakeProfile({}, ())):
                state = ScanState(
                    scan_id="scan-2",
                    project="demo",
                    plan_id="baseline",
                    target="staging",
                    target_repo="/tmp/demo",
                    requested_evidence_level="observe_only",
                    started_at=utc_now(),
                    status="finished",
                    finished_at=utc_now(),
                )
                state.completed.append(ScanModuleState(module_id="done", status="completed"))
                write_scan_state(state)
                write_scan_summary(state)
                code, stdout, _stderr = _run_main_capture(["scan", "status", "demo", "--scan-id", "scan-2"])
        self.assertEqual(code, 0)
        self.assertIn("scan_id: scan-2", stdout)
        self.assertIn("completed: done", stdout)

    def test_scan_status_for_missing_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _scan_test_context(tmp, FakeProfile({}, ())):
                code, _stdout, stderr = _run_main_capture(["scan", "status", "demo", "--scan-id", "missing"])
        self.assertEqual(code, 1)
        self.assertIn("Scan state not found", stderr)

    def test_heartbeat_file_is_written_during_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile({"one": FakeModule("one", (EvidenceLevel.OBSERVE_ONLY,), calls)}, ("one",))
            with _scan_test_context(tmp, profile):
                code = _run_main(["scan", "demo", "baseline", "--target", "staging", "--target-repo", "/tmp/demo"])
                state = _only_state("demo", tmp)
                heartbeat = heartbeat_path("demo", state.scan_id)
                self.assertTrue(heartbeat.exists())
                content = heartbeat.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertIn('"status": "finished"', content)
        self.assertIn('"completed_count": 1', content)

    def test_max_duration_skips_remaining_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile(
                {
                    "one": FakeModule("one", (EvidenceLevel.OBSERVE_ONLY,), calls),
                    "two": FakeModule("two", (EvidenceLevel.OBSERVE_ONLY,), calls),
                },
                ("one", "two"),
            )
            with _scan_test_context(tmp, profile):
                code = _run_main(
                    [
                        "scan",
                        "demo",
                        "baseline",
                        "--target",
                        "staging",
                        "--target-repo",
                        "/tmp/demo",
                        "--max-duration-minutes",
                        "0",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(calls, [])
            state = _only_state("demo", tmp)
            self.assertEqual([item.module_id for item in state.skipped], ["one", "two"])
            self.assertEqual(state.skipped[0].error, "max duration exceeded")

    def test_delay_option_is_recorded_without_slow_sleep(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls: list[tuple[str, str]] = []
            profile = FakeProfile({"one": FakeModule("one", (EvidenceLevel.OBSERVE_ONLY,), calls)}, ("one",))
            with _scan_test_context(tmp, profile), patch("pentest_harness.cli.time.sleep") as sleep:
                code = _run_main(["scan", "demo", "baseline", "--target", "staging", "--target-repo", "/tmp/demo", "--delay-ms", "250"])
            self.assertEqual(code, 0)
            sleep.assert_not_called()
            state = _only_state("demo", tmp)
            self.assertEqual(state.delay_ms, 250)


class FakeModule:
    def __init__(self, module_id: str, evidence_levels: tuple[EvidenceLevel, ...], calls: list[tuple[str, str]], *, fail: bool = False):
        self.metadata = ModuleMetadata(
            id=module_id,
            title=module_id,
            safety_level=SafetyLevel.STATIC_ONLY if evidence_levels == (EvidenceLevel.OBSERVE_ONLY,) else SafetyLevel.HTTP_SAFE,
            evidence_levels_supported=evidence_levels,
            requires_authorization_ticket=False,
        )
        self.calls = calls
        self.fail = fail

    def run(self, context):
        self.calls.append((self.metadata.id, context.options.evidence_level.value))
        if self.fail:
            raise RuntimeError("module failed")
        return ModuleResult(outcome="passed", summary=f"{self.metadata.id} passed")


class FakeProfile:
    adapter_allowed_staging_urls = ("https://staging.example.test",)
    adapter_allowed_production_urls = ("https://prod.example.test",)
    adapter_forbidden_urls = ()

    def __init__(self, modules, module_ids):
        self._modules = modules
        self._plan = ScanPlan(
            id="baseline",
            title="Baseline",
            project="demo",
            module_ids=module_ids,
            default_target="staging",
            max_evidence_level=EvidenceLevel.NON_MUTATING_PROBE,
            description="test",
        )

    def modules(self, *, security_map_write=False):
        return self._modules

    def scan_plans(self):
        return {"baseline": self._plan}

    def target(self, environment):
        if environment == "production":
            return TargetProfile(environment="production", base_url="https://prod.example.test")
        return TargetProfile(environment="staging", base_url="https://staging.example.test")

    def rules_of_engagement(self, target_repo):
        return RulesOfEngagement(
            allowed_staging_urls=("https://staging.example.test",),
            allowed_production_urls=("https://prod.example.test",),
        )


@contextmanager
def _scan_test_context(tmp, profile):
    with patch("pentest_harness.cli._profile", lambda project: profile), patch.object(artifacts, "RUNTIME_ROOT", Path(tmp)):
        yield


def _only_state(project, tmp):
    scan_root = Path(tmp) / project / "scans"
    scan_ids = [path.name for path in scan_root.iterdir() if path.is_dir()]
    assert len(scan_ids) == 1
    with patch.object(artifacts, "RUNTIME_ROOT", Path(tmp)):
        return load_scan_state(project, scan_ids[0])


def _run_main(argv):
    return _run_main_capture(argv)[0]


def _run_main_capture(argv):
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
