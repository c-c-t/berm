"""Tests for new SimpleEvaluator features (multi-resource, has_keys, is_not_empty)."""

import pytest

from berm.evaluators.simple import SimpleEvaluator
from berm.models.rule import Rule


def test_evaluator_multiple_resource_types():
    """Test evaluation with multiple resource types."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="multi-type",
        name="Multi Type Rule",
        resource_types=["aws_s3_bucket", "aws_db_instance", "aws_lambda_function"],
        severity="error",
        property="tags",
        has_keys=["Environment"],
        message="Resource must have Environment tag",
    )

    resources = [
        {
            "address": "aws_s3_bucket.bucket",
            "type": "aws_s3_bucket",
            "name": "bucket",
            "values": {"tags": {"Environment": "prod", "Owner": "team"}},
        },
        {
            "address": "aws_db_instance.db",
            "type": "aws_db_instance",
            "name": "db",
            "values": {"tags": {}},  # Missing Environment tag
        },
        {
            "address": "aws_lambda_function.func",
            "type": "aws_lambda_function",
            "name": "func",
            "values": {"tags": {"Environment": "dev"}},
        },
        {
            "address": "aws_instance.instance",
            "type": "aws_instance",
            "name": "instance",
            "values": {"tags": {}},  # Different type, should be ignored
        },
    ]

    violations = evaluator.evaluate(rule, resources)
    # Only aws_db_instance.db should violate (aws_instance is not in resource_types)
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_db_instance.db"


def test_evaluator_has_keys_operator():
    """Test has_keys operator for tag validation."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="tag-keys",
        name="Tag Keys Rule",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        has_keys=["Environment", "Owner", "CostCenter"],
        message="Must have all required tags",
    )

    # Compliant resource
    resources_good = [
        {
            "address": "aws_s3_bucket.good",
            "type": "aws_s3_bucket",
            "name": "good",
            "values": {
                "tags": {
                    "Environment": "prod",
                    "Owner": "team-a",
                    "CostCenter": "12345",
                    "Extra": "ok",
                }
            },
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0


def test_evaluator_has_keys_missing_key():
    """Test has_keys detects missing required keys."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="tag-keys",
        name="Tag Keys Rule",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        has_keys=["Environment", "Owner", "CostCenter"],
        message="Must have all required tags",
    )

    # Missing CostCenter
    resources_bad = [
        {
            "address": "aws_s3_bucket.bad",
            "type": "aws_s3_bucket",
            "name": "bad",
            "values": {"tags": {"Environment": "prod", "Owner": "team-a"}},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1
    assert "has keys" in violations[0].message


def test_evaluator_has_keys_non_dict():
    """Test has_keys handles non-dict values gracefully."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="tag-keys",
        name="Tag Keys Rule",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        has_keys=["Environment"],
        message="Must have tags",
    )

    # tags is a string instead of dict
    resources_bad = [
        {
            "address": "aws_s3_bucket.bad",
            "type": "aws_s3_bucket",
            "name": "bad",
            "values": {"tags": "not-a-dict"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1


def test_evaluator_is_not_empty_dict():
    """Test is_not_empty with dict values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="not-empty",
        name="Not Empty Rule",
        resource_type="aws_s3_bucket",
        severity="warning",
        property="tags",
        is_not_empty=True,
        message="Should have tags",
    )

    # Non-empty dict
    resources_good = [
        {
            "address": "aws_s3_bucket.good",
            "type": "aws_s3_bucket",
            "name": "good",
            "values": {"tags": {"key": "value"}},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Empty dict
    resources_bad = [
        {
            "address": "aws_s3_bucket.bad",
            "type": "aws_s3_bucket",
            "name": "bad",
            "values": {"tags": {}},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1
    assert "is not empty" in violations[0].message


def test_evaluator_is_not_empty_list():
    """Test is_not_empty with list values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="not-empty",
        name="Not Empty Rule",
        resource_type="aws_resource",
        severity="warning",
        property="items",
        is_not_empty=True,
        message="Should have items",
    )

    # Non-empty list
    resources_good = [
        {
            "address": "aws_resource.good",
            "type": "aws_resource",
            "name": "good",
            "values": {"items": ["item1", "item2"]},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Empty list
    resources_bad = [
        {
            "address": "aws_resource.bad",
            "type": "aws_resource",
            "name": "bad",
            "values": {"items": []},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1


def test_evaluator_is_not_empty_string():
    """Test is_not_empty with string values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="not-empty",
        name="Not Empty Rule",
        resource_type="aws_resource",
        severity="error",
        property="name",
        is_not_empty=True,
        message="Name is required",
    )

    # Non-empty string
    resources_good = [
        {
            "address": "aws_resource.good",
            "type": "aws_resource",
            "name": "good",
            "values": {"name": "valid-name"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Empty string
    resources_bad = [
        {
            "address": "aws_resource.bad",
            "type": "aws_resource",
            "name": "bad",
            "values": {"name": ""},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1


def test_evaluator_is_not_empty_none():
    """Test is_not_empty detects None/missing values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="not-empty",
        name="Not Empty Rule",
        resource_type="aws_resource",
        severity="error",
        property="tags",
        is_not_empty=True,
        message="Tags required",
    )

    # Property missing (will be None from get_nested_property)
    resources_bad = [
        {
            "address": "aws_resource.bad",
            "type": "aws_resource",
            "name": "bad",
            "values": {},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1
    assert "not found" in violations[0].message


def test_evaluator_tags_all_fallback_when_tags_empty():
    """Provider default_tags: tags is null/empty but tags_all carries the tags."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="required-tags",
        name="Required Application tag",
        resource_type="aws_iam_instance_profile",
        severity="error",
        property="tags",
        has_keys=["Application"],
        message="Resource {{resource_name}} must have Application tags",
    )

    resources = [
        # tags is None (set entirely via provider default_tags)
        {
            "address": "module.api.aws_iam_instance_profile.api_ec2",
            "type": "aws_iam_instance_profile",
            "name": "api_ec2",
            "values": {
                "tags": None,
                "tags_all": {"Application": "api", "Environment": "prod"},
            },
        },
        # tags is an empty dict
        {
            "address": "module.api.aws_iam_instance_profile.api_ec2_2",
            "type": "aws_iam_instance_profile",
            "name": "api_ec2_2",
            "values": {
                "tags": {},
                "tags_all": {"Application": "api"},
            },
        },
    ]

    violations = evaluator.evaluate(rule, resources)
    assert len(violations) == 0


def test_evaluator_tags_all_supersedes_partial_tags():
    """tags has some keys, the required one comes from default_tags via tags_all."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="required-tags",
        name="Required Application tag",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        has_keys=["Application"],
        message="Must have Application tag",
    )

    resources = [
        {
            "address": "aws_s3_bucket.b",
            "type": "aws_s3_bucket",
            "name": "b",
            "values": {
                "tags": {"Environment": "prod"},
                "tags_all": {"Environment": "prod", "Application": "billing"},
            },
        }
    ]

    violations = evaluator.evaluate(rule, resources)
    assert len(violations) == 0


def test_evaluator_tags_all_nested_key_fallback():
    """Nested tag path (tags.Application) resolves via tags_all."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="app-tag-value",
        name="Application tag must be set",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags.Application",
        is_not_empty=True,
        message="Application tag required",
    )

    resources = [
        {
            "address": "aws_s3_bucket.b",
            "type": "aws_s3_bucket",
            "name": "b",
            "values": {
                "tags": None,
                "tags_all": {"Application": "billing"},
            },
        }
    ]

    violations = evaluator.evaluate(rule, resources)
    assert len(violations) == 0


def test_evaluator_tags_still_fails_when_tags_all_missing_key():
    """Effective tags (tags_all) genuinely missing the key still violates."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="required-tags",
        name="Required Application tag",
        resource_type="aws_iam_instance_profile",
        severity="error",
        property="tags",
        has_keys=["Application"],
        message="Must have Application tag",
    )

    resources = [
        {
            "address": "aws_iam_instance_profile.p",
            "type": "aws_iam_instance_profile",
            "name": "p",
            "values": {
                "tags": None,
                "tags_all": {"Environment": "prod"},  # no Application
            },
        }
    ]

    violations = evaluator.evaluate(rule, resources)
    assert len(violations) == 1


def test_evaluator_tags_without_tags_all_uses_tags():
    """Plans without default_tags (no tags_all) still evaluate tags directly."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="required-tags",
        name="Required Application tag",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        has_keys=["Application"],
        message="Must have Application tag",
    )

    resources = [
        {
            "address": "aws_s3_bucket.b",
            "type": "aws_s3_bucket",
            "name": "b",
            "values": {"tags": {"Application": "x"}},  # no tags_all present
        }
    ]

    violations = evaluator.evaluate(rule, resources)
    assert len(violations) == 0


def test_evaluator_backwards_compatibility_single_resource_type():
    """Test that existing rules with single resource_type still work."""
    evaluator = SimpleEvaluator()

    # Old-style rule with single resource_type
    rule = Rule(
        id="old-style",
        name="Old Style Rule",
        resource_type="aws_s3_bucket",
        severity="error",
        property="versioning.enabled",
        equals=True,
        message="Versioning must be enabled",
    )

    resources = [
        {
            "address": "aws_s3_bucket.compliant",
            "type": "aws_s3_bucket",
            "name": "compliant",
            "values": {"versioning": {"enabled": True}},
        },
        {
            "address": "aws_s3_bucket.non_compliant",
            "type": "aws_s3_bucket",
            "name": "non_compliant",
            "values": {"versioning": {"enabled": False}},
        },
        {
            "address": "aws_db_instance.db",
            "type": "aws_db_instance",
            "name": "db",
            "values": {"versioning": {"enabled": False}},
        },
    ]

    violations = evaluator.evaluate(rule, resources)
    # Should only check S3 buckets, find 1 violation
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_s3_bucket.non_compliant"
