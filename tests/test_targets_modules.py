import unittest
from dataclasses import replace

from pentest_harness.cli import build_parser
from pentest_harness.adapters.cheddar.profile import get_profile
from pentest_harness.core.modules import EvidenceLevel, ModuleMetadata, SafetyLevel, validate_module_metadata
from pentest_harness.core.roe import RulesOfEngagement
from pentest_harness.core.targets import TargetGuardError, validate_target


class TargetAndModuleTests(unittest.TestCase):
    def test_forbids_legacy_cheddar_staging_host(self):
        profile = get_profile()
        module = profile.modules()["webhook-negative"]
        options = _options("staging", EvidenceLevel.NON_MUTATING_PROBE)
        target = replace(profile.target("staging"), base_url="https://staging-api.cheddar.biz")
        with self.assertRaisesRegex(TargetGuardError, "legacy/wrong Heroku"):
            validate_target(
                project="cheddar",
                target=target,
                roe=RulesOfEngagement(forbidden_urls=("https://staging-api.cheddar.biz",)),
                module=module,
                options=options,
                adapter_allowed_staging_urls=profile.adapter_allowed_staging_urls,
                adapter_allowed_production_urls=profile.adapter_allowed_production_urls,
                adapter_forbidden_urls=profile.adapter_forbidden_urls,
            )

    def test_production_requires_flags_and_module_permission(self):
        profile = get_profile()
        module = profile.modules()["webhook-negative"]
        options = _options("production", EvidenceLevel.NON_MUTATING_PROBE)
        with self.assertRaisesRegex(TargetGuardError, "allow-production|not production allowed"):
            validate_target(
                project="cheddar",
                target=profile.target("production"),
                roe=RulesOfEngagement(allowed_production_urls=("https://api.cheddar.biz",)),
                module=module,
                options=options,
                adapter_allowed_staging_urls=profile.adapter_allowed_staging_urls,
                adapter_allowed_production_urls=profile.adapter_allowed_production_urls,
                adapter_forbidden_urls=profile.adapter_forbidden_urls,
            )

    def test_production_requires_explicit_evidence_level(self):
        profile = get_profile()

        class ProdModule:
            metadata = ModuleMetadata(
                id="prod-safe",
                title="Prod Safe",
                safety_level=SafetyLevel.HTTP_SAFE,
                evidence_levels_supported=(EvidenceLevel.NON_MUTATING_PROBE,),
                production_allowed=True,
            )

        options = _options("production", None)
        options = replace(options, allow_production=True, authorization_ticket="AUTH-123")
        with self.assertRaisesRegex(TargetGuardError, "evidence-level"):
            validate_target(
                project="cheddar",
                target=profile.target("production"),
                roe=RulesOfEngagement(allowed_production_urls=("https://api.cheddar.biz",)),
                module=ProdModule(),
                options=options,
                adapter_allowed_staging_urls=profile.adapter_allowed_staging_urls,
                adapter_allowed_production_urls=profile.adapter_allowed_production_urls,
                adapter_forbidden_urls=profile.adapter_forbidden_urls,
            )

    def test_argparse_preserves_omitted_evidence_level(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "run",
                "cheddar",
                "webhook-negative",
                "--target",
                "production",
                "--target-repo",
                "/tmp/cheddar",
                "--allow-production",
                "--authorization-ticket",
                "AUTH-123",
            ]
        )
        self.assertIsNone(args.evidence_level)

    def test_production_urls_are_not_allowed_for_staging(self):
        profile = get_profile()
        module = profile.modules()["webhook-negative"]
        options = _options("staging", EvidenceLevel.NON_MUTATING_PROBE)
        target = replace(profile.target("staging"), base_url="https://api.cheddar.biz")
        with self.assertRaisesRegex(TargetGuardError, "not allowed"):
            validate_target(
                project="cheddar",
                target=target,
                roe=RulesOfEngagement(allowed_staging_urls=("https://staging-api-aws.cheddar.biz",)),
                module=module,
                options=options,
                adapter_allowed_staging_urls=profile.adapter_allowed_staging_urls,
                adapter_allowed_production_urls=profile.adapter_allowed_production_urls,
                adapter_forbidden_urls=profile.adapter_forbidden_urls,
            )

    def test_rejects_invalid_metadata(self):
        metadata = ModuleMetadata(
            id="bad",
            title="Bad",
            safety_level=SafetyLevel.STATE_CHANGING,
            evidence_levels_supported=(EvidenceLevel.OBSERVE_ONLY,),
        )
        with self.assertRaises(ValueError):
            validate_module_metadata(metadata)

    def test_state_changing_requires_explicit_approval(self):
        profile = get_profile()

        class Module:
            metadata = ModuleMetadata(
                id="state-change",
                title="State Change",
                safety_level=SafetyLevel.STATE_CHANGING,
                evidence_levels_supported=(EvidenceLevel.SAFE_MUTATION,),
            )

        options = _options("staging", EvidenceLevel.SAFE_MUTATION)
        with self.assertRaisesRegex(TargetGuardError, "approve-state-change"):
            validate_target(
                project="cheddar",
                target=profile.target("staging"),
                roe=RulesOfEngagement(allowed_staging_urls=("https://staging-api-aws.cheddar.biz",)),
                module=Module(),
                options=options,
                adapter_allowed_staging_urls=profile.adapter_allowed_staging_urls,
                adapter_allowed_production_urls=profile.adapter_allowed_production_urls,
                adapter_forbidden_urls=profile.adapter_forbidden_urls,
            )


def _options(target: str, evidence_level: EvidenceLevel | None):
    from pentest_harness.core.modules import RunOptions

    return RunOptions(project="cheddar", target_environment=target, target_repo="/tmp/repo", evidence_level=evidence_level)


if __name__ == "__main__":
    unittest.main()
