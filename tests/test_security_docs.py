import json
import socket
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from pentest_harness.cli import main


class SecurityDocsProposalTests(unittest.TestCase):
    def test_security_docs_propose_command_exists(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                code, stdout, stderr = _run_main(_propose_args(repo))
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Security docs proposal created:", stdout)

    def test_proposal_is_written_under_runtime_not_target_repo(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            before = _snapshot(repo)
            with _runtime_context(runtime_tmp):
                code, stdout, _stderr = _run_main(_propose_args(repo))
            proposal_path = _path_from_stdout(stdout)
            proposal_exists = proposal_path.is_dir()
            proposal_under_runtime = str(proposal_path).startswith(str(Path(runtime_tmp) / "cheddar" / "security-doc-proposals"))
            after = _snapshot(repo)
        self.assertEqual(code, 0)
        self.assertTrue(proposal_exists)
        self.assertTrue(proposal_under_runtime)
        self.assertEqual(before, after)

    def test_proposal_json_has_stable_fields(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_propose_args(repo))
            proposal_path = _path_from_stdout(stdout)
            payload = json.loads((proposal_path / "proposal.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["project"], "cheddar")
        self.assertEqual(payload["status"], "proposed")
        self.assertIn("proposal_id", payload)
        self.assertIn("created_at", payload)
        self.assertIn("target_repo", payload)
        self.assertIn("sources", payload)
        self.assertEqual(payload["proposed_files"], ["summary.md", "proposed-updates.md"])

    def test_proposed_updates_file_is_created(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_propose_args(repo))
            proposal_path = _path_from_stdout(stdout)
            proposed_updates_exists = (proposal_path / "proposed-updates.md").is_file()
            summary_exists = (proposal_path / "summary.md").is_file()
        self.assertTrue(proposed_updates_exists)
        self.assertTrue(summary_exists)

    def test_proposal_includes_webhook_pending_knowledge_from_docs_and_recon(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            _write_recon_report(runtime_tmp)
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_propose_args(repo))
            proposal_path = _path_from_stdout(stdout)
            text = (proposal_path / "proposed-updates.md").read_text(encoding="utf-8")
        self.assertIn("webhook replay/freshness target coverage as pending review", text)
        self.assertIn("Inbound webhook surfaces were identified during campaign recon.", text)
        self.assertIn("Application-level timestamp freshness validation was not found in recon.", text)
        self.assertIn("Route-level replay or delivery ID validation was not found in recon.", text)
        self.assertIn("Downstream idempotency was observed", text)

    def test_proposal_does_not_include_obvious_sensitive_values_from_sample_inputs(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            _write_recon_report(
                runtime_tmp,
                extra="Bearer abcdefghijklmnop Authorization: secret Cookie: session=secret request body: raw",
            )
            with _runtime_context(runtime_tmp):
                _code, stdout, _stderr = _run_main(_propose_args(repo))
            proposal_path = _path_from_stdout(stdout)
            combined = "\n".join(path.read_text(encoding="utf-8") for path in proposal_path.glob("*"))
        self.assertNotIn("abcdefghijklmnop", combined)
        self.assertNotIn("session=secret", combined)
        self.assertNotIn("request body: raw", combined.lower())

    def test_missing_security_folder_is_handled_gracefully(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            with _runtime_context(runtime_tmp):
                code, stdout, stderr = _run_main(_propose_args(Path(repo_tmp)))
            proposal_path = _path_from_stdout(stdout)
            text = (proposal_path / "proposed-updates.md").read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Missing .security Folder", text)

    def test_command_does_not_modify_target_security(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            before = _snapshot(repo / ".security")
            with _runtime_context(runtime_tmp):
                code, _stdout, _stderr = _run_main(_propose_args(repo))
            after = _snapshot(repo / ".security")
        self.assertEqual(code, 0)
        self.assertEqual(before, after)

    def test_no_http_requests_are_sent(self):
        with tempfile.TemporaryDirectory() as runtime_tmp, tempfile.TemporaryDirectory() as repo_tmp:
            repo = _make_security_repo(repo_tmp)
            with _runtime_context(runtime_tmp), patch.object(socket, "create_connection", side_effect=AssertionError("network attempted")):
                code, _stdout, _stderr = _run_main(_propose_args(repo))
        self.assertEqual(code, 0)


def _propose_args(target_repo: Path) -> list[str]:
    return ["security-docs", "propose", "cheddar", "--target-repo", str(target_repo)]


def _make_security_repo(root: str) -> Path:
    repo = Path(root)
    security = repo / ".security"
    (security / "invariants").mkdir(parents=True)
    (security / "webhooks").mkdir()
    (security / "flows").mkdir()
    (security / "rules-of-engagement.md").write_text("Allowed staging URLs\n- https://staging.example.test\n", encoding="utf-8")
    (security / "attack-surface.md").write_text("| Method | Path | File | Handler | Auth | Money |\n| POST | /webhook | app.py | handler | Provider signature | Direct |\n", encoding="utf-8")
    (security / "invariants" / "webhook-trust.md").write_text("Webhook replay freshness stale nonce invariant is pending.\n", encoding="utf-8")
    (security / "webhooks" / "provider.md").write_text("Webhook signature and replay behavior must be reviewed.\n", encoding="utf-8")
    (security / "flows" / "webhooks.md").write_text("Webhook flow uses staging fixtures only.\n", encoding="utf-8")
    return repo


def _write_recon_report(runtime_tmp: str, extra: str = "") -> None:
    path = Path(runtime_tmp) / "cheddar" / "campaigns" / "webhook-replay-freshness-test" / "recon-report.md"
    path.parent.mkdir(parents=True)
    path.write_text(
        "\n".join(
            [
                "Inbound provider webhook surfaces were found.",
                "Signature checks and authorization checks were found.",
                "Timestamp freshness validation was not found in recon.",
                "Replay/delivery ID validation was not found in recon.",
                "Downstream idempotency is not boundary replay rejection.",
                extra,
            ]
        ),
        encoding="utf-8",
    )


def _path_from_stdout(stdout: str) -> Path:
    for line in stdout.splitlines():
        if line.startswith("path: "):
            return Path(line.removeprefix("path: "))
    raise AssertionError(f"No path line in output: {stdout}")


def _snapshot(root: Path) -> dict[str, str]:
    return {str(path.relative_to(root)): path.read_text(encoding="utf-8") for path in sorted(root.rglob("*")) if path.is_file()}


@contextmanager
def _runtime_context(runtime_tmp: str):
    from pentest_harness.core import artifacts

    with patch.object(artifacts, "RUNTIME_ROOT", Path(runtime_tmp)):
        yield


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


if __name__ == "__main__":
    unittest.main()
