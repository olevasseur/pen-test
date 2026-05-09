import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pentest_harness.core import artifacts
from pentest_harness.core.ledger import LedgerEntry, append_ledger, read_ledger
from pentest_harness.core.reporting import export_snapshot, latest_report


class LedgerReportingTests(unittest.TestCase):
    def test_ledger_and_export_are_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(artifacts, "RUNTIME_ROOT", Path(tmp)):
                # Patch ledger module's imported ensure function path through artifacts behavior.
                import pentest_harness.core.ledger as ledger_module
                import pentest_harness.core.reporting as reporting_module

                with patch.object(ledger_module, "ensure_runtime_dirs", artifacts.ensure_runtime_dirs), patch.object(
                    reporting_module, "ensure_runtime_dirs", artifacts.ensure_runtime_dirs
                ):
                    append_ledger(
                        "demo",
                        LedgerEntry(
                            run_id="run-1",
                            module_id="mod",
                            target_profile="demo",
                            target_environment="staging",
                            base_url="https://staging.example.com",
                            safety_level="static_only",
                            evidence_level="observe_only",
                            production_authorization_ticket=None,
                            timestamp="2026-05-09T00:00:00Z",
                            outcome="passed",
                            summary="Bearer abcdefghijklmnop",
                            finding_ids=[],
                            artifact_references=[],
                            linked_security_docs={},
                            security_map_drift_detected=False,
                            security_map_update_proposed=False,
                            security_map_update_written=False,
                        ),
                    )
                    entries = read_ledger("demo")
                    self.assertIn("[REDACTED]", entries[0]["summary"])
                    report = latest_report("demo")
                    self.assertNotIn("abcdefghijklmnop", report)
                    export_snapshot("demo", Path(tmp) / "export")
                    exported = json.loads((Path(tmp) / "export" / "ledger.sanitized.json").read_text(encoding="utf-8"))
                    self.assertIn("[REDACTED]", exported[0]["summary"])


if __name__ == "__main__":
    unittest.main()
