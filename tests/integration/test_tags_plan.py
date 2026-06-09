"""End-to-end regression tests for tag extraction across resource representations.

Exercises the real plan loader + SimpleEvaluator against tests/fixtures/tags-plan.json,
which contains the three shapes that previously produced false positives:

- a data source (aws_ami lookup) that must be skipped entirely,
- an aws_autoscaling_group tagged via repeatable `tag` blocks (no tags_all),
- a resource tagged only via provider default_tags (tags_all populated, tags null).
"""

from pathlib import Path

import pytest

from berm.evaluators.simple import SimpleEvaluator
from berm.loaders.terraform import load_terraform_plan
from berm.models.rule import Rule


@pytest.fixture
def tags_plan_file() -> Path:
    return Path(__file__).parent.parent / "fixtures" / "tags-plan.json"


@pytest.fixture
def required_tags_rule() -> Rule:
    """Required-tag rule covering every taggable resource type in the fixture."""
    return Rule(
        id="required-tags",
        name="Resources must have Application and map-migrated tags",
        resource_types=["aws_ami", "aws_autoscaling_group", "aws_instance"],
        severity="error",
        property="tags",
        has_keys=["Application", "map-migrated"],
        message="{{resource_name}} must have Application and map-migrated tags",
    )


def test_no_false_positives_across_tag_representations(tags_plan_file, required_tags_rule):
    """The full plan should produce zero violations: every managed resource is tagged."""
    resources = load_terraform_plan(str(tags_plan_file), _allow_absolute=True)

    violations = SimpleEvaluator().evaluate(required_tags_rule, resources)

    assert violations == [], f"Unexpected violations: {[v.resource_name for v in violations]}"


def test_data_source_is_loaded_but_not_evaluated(tags_plan_file, required_tags_rule):
    """The data source is present in the plan (mode='data') yet never produces a violation."""
    resources = load_terraform_plan(str(tags_plan_file), _allow_absolute=True)

    ami = next(r for r in resources if r["address"] == "module.api.data.aws_ami.ubuntu")
    assert ami["mode"] == "data"

    violations = SimpleEvaluator().evaluate(required_tags_rule, resources)
    assert all("aws_ami" not in v.resource_name for v in violations)


def test_missing_required_tag_still_detected_end_to_end(tags_plan_file):
    """A genuinely missing tag is still reported (no over-suppression)."""
    resources = load_terraform_plan(str(tags_plan_file), _allow_absolute=True)

    rule = Rule(
        id="required-cost-center",
        name="Resources must have CostCenter tag",
        resource_types=["aws_autoscaling_group", "aws_instance"],
        severity="error",
        property="tags",
        has_keys=["CostCenter"],  # not present on any fixture resource
        message="{{resource_name}} must have a CostCenter tag",
    )

    violations = SimpleEvaluator().evaluate(rule, resources)
    addresses = {v.resource_name for v in violations}

    assert addresses == {
        "module.neo4j.aws_autoscaling_group.neo4j",
        "module.api.aws_instance.api",
    }
