"""Tests for simple evaluator."""

import pytest

from berm.evaluators.simple import SimpleEvaluator
from berm.models.rule import RequiredResource, Rule
from berm.models.violation import Violation


def test_evaluator_no_violations(sample_rule):
    """Test evaluation when all resources comply."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_s3_bucket.compliant",
            "type": "aws_s3_bucket",
            "name": "compliant",
            "values": {
                "bucket": "my-bucket",
                "versioning": {"enabled": True},
            },
        }
    ]

    violations = evaluator.evaluate(sample_rule, resources)
    assert len(violations) == 0


def test_evaluator_finds_violation(sample_rule):
    """Test evaluation finds violations."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_s3_bucket.non_compliant",
            "type": "aws_s3_bucket",
            "name": "non_compliant",
            "values": {
                "bucket": "my-bucket",
                "versioning": {"enabled": False},
            },
        }
    ]

    violations = evaluator.evaluate(sample_rule, resources)
    assert len(violations) == 1
    assert isinstance(violations[0], Violation)
    assert violations[0].resource_name == "aws_s3_bucket.non_compliant"
    assert violations[0].severity == "error"


def test_evaluator_missing_property(sample_rule):
    """Test evaluation when property doesn't exist."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_s3_bucket.missing",
            "type": "aws_s3_bucket",
            "name": "missing",
            "values": {
                "bucket": "my-bucket",
                # versioning property is missing
            },
        }
    ]

    violations = evaluator.evaluate(sample_rule, resources)
    assert len(violations) == 1
    assert "not found" in violations[0].message


def test_evaluator_filters_by_resource_type(sample_rule):
    """Test that evaluator only checks matching resource types."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_s3_bucket.bucket",
            "type": "aws_s3_bucket",
            "name": "bucket",
            "values": {
                "versioning": {"enabled": False},  # Violates rule
            },
        },
        {
            "address": "aws_db_instance.database",
            "type": "aws_db_instance",
            "name": "database",
            "values": {
                "versioning": {"enabled": False},  # Should be ignored (wrong type)
            },
        },
    ]

    violations = evaluator.evaluate(sample_rule, resources)
    # Only S3 bucket should be checked
    assert len(violations) == 1
    assert violations[0].resource_type == "aws_s3_bucket"


def test_evaluator_multiple_resources(sample_rule):
    """Test evaluation with multiple resources of same type."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_s3_bucket.compliant",
            "type": "aws_s3_bucket",
            "name": "compliant",
            "values": {"versioning": {"enabled": True}},
        },
        {
            "address": "aws_s3_bucket.non_compliant_1",
            "type": "aws_s3_bucket",
            "name": "non_compliant_1",
            "values": {"versioning": {"enabled": False}},
        },
        {
            "address": "aws_s3_bucket.non_compliant_2",
            "type": "aws_s3_bucket",
            "name": "non_compliant_2",
            "values": {"versioning": {"enabled": False}},
        },
    ]

    violations = evaluator.evaluate(sample_rule, resources)
    assert len(violations) == 2
    addresses = [v.resource_name for v in violations]
    assert "aws_s3_bucket.non_compliant_1" in addresses
    assert "aws_s3_bucket.non_compliant_2" in addresses


def test_evaluator_warning_severity(sample_warning_rule):
    """Test evaluation with warning severity."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_db_instance.db",
            "type": "aws_db_instance",
            "name": "db",
            "values": {
                "backup_retention_period": 3,  # Should be 7
            },
        }
    ]

    violations = evaluator.evaluate(sample_warning_rule, resources)
    assert len(violations) == 1
    assert violations[0].severity == "warning"


def test_evaluator_evaluate_all(sample_rule, sample_warning_rule):
    """Test evaluating multiple rules."""
    evaluator = SimpleEvaluator()

    resources = [
        {
            "address": "aws_s3_bucket.bucket",
            "type": "aws_s3_bucket",
            "name": "bucket",
            "values": {"versioning": {"enabled": False}},
        },
        {
            "address": "aws_db_instance.db",
            "type": "aws_db_instance",
            "name": "db",
            "values": {"backup_retention_period": 3},
        },
    ]

    rules = [sample_rule, sample_warning_rule]
    violations = evaluator.evaluate_all(rules, resources)

    assert len(violations) == 2
    # One error from S3 rule, one warning from DB rule
    errors = [v for v in violations if v.severity == "error"]
    warnings = [v for v in violations if v.severity == "warning"]
    assert len(errors) == 1
    assert len(warnings) == 1


def test_evaluator_value_types():
    """Test evaluation with different value types."""
    evaluator = SimpleEvaluator()

    # String comparison
    rule_string = Rule(
        id="test-string",
        name="String Test",
        resource_type="aws_resource",
        severity="error",
        property="status",
        equals="Enabled",
        message="Test",
    )

    resources_string = [
        {
            "address": "aws_resource.good",
            "type": "aws_resource",
            "name": "good",
            "values": {"status": "Enabled"},
        }
    ]

    violations = evaluator.evaluate(rule_string, resources_string)
    assert len(violations) == 0

    # Integer comparison
    rule_int = Rule(
        id="test-int",
        name="Int Test",
        resource_type="aws_resource",
        severity="error",
        property="count",
        equals=5,
        message="Test",
    )

    resources_int = [
        {
            "address": "aws_resource.good",
            "type": "aws_resource",
            "name": "good",
            "values": {"count": 5},
        }
    ]

    violations = evaluator.evaluate(rule_int, resources_int)
    assert len(violations) == 0


def test_evaluator_value_coercion():
    """Test that evaluator handles type coercion."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_resource",
        severity="error",
        property="enabled",
        equals=True,
        message="Test",
    )

    # String "true" should match boolean True
    resources = [
        {
            "address": "aws_resource.test",
            "type": "aws_resource",
            "name": "test",
            "values": {"enabled": "true"},
        }
    ]

    violations = evaluator.evaluate(rule, resources)
    assert len(violations) == 0


def test_evaluator_contains_string():
    """Test contains operator with string values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test-contains",
        name="Contains Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="bucket_name",
        contains="prod",
        message="Bucket name must contain 'prod'",
    )

    # Compliant resource
    resources_good = [
        {
            "address": "aws_s3_bucket.production",
            "type": "aws_s3_bucket",
            "name": "production",
            "values": {"bucket_name": "my-prod-bucket"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Non-compliant resource
    resources_bad = [
        {
            "address": "aws_s3_bucket.staging",
            "type": "aws_s3_bucket",
            "name": "staging",
            "values": {"bucket_name": "my-staging-bucket"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1
    assert "contains 'prod'" in violations[0].message


def test_evaluator_contains_list():
    """Test contains operator with list values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test-contains-list",
        name="Contains List Test",
        resource_type="aws_resource",
        severity="error",
        property="tags",
        contains="Environment",
        message="Tags must contain 'Environment'",
    )

    # Compliant resource
    resources_good = [
        {
            "address": "aws_resource.tagged",
            "type": "aws_resource",
            "name": "tagged",
            "values": {"tags": ["Environment", "Owner", "Project"]},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Non-compliant resource
    resources_bad = [
        {
            "address": "aws_resource.untagged",
            "type": "aws_resource",
            "name": "untagged",
            "values": {"tags": ["Owner", "Project"]},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1


def test_evaluator_in_list():
    """Test in operator with list of allowed values."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test-in",
        name="In List Test",
        resource_type="aws_instance",
        severity="error",
        property="instance_type",
        **{"in": ["t3.micro", "t3.small", "t3.medium"]},
        message="Instance type must be t3.micro, t3.small, or t3.medium",
    )

    # Compliant resource
    resources_good = [
        {
            "address": "aws_instance.allowed",
            "type": "aws_instance",
            "name": "allowed",
            "values": {"instance_type": "t3.small"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Non-compliant resource
    resources_bad = [
        {
            "address": "aws_instance.forbidden",
            "type": "aws_instance",
            "name": "forbidden",
            "values": {"instance_type": "t3.xlarge"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1
    assert "in [" in violations[0].message


def test_evaluator_regex_match():
    """Test regex_match operator."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test-regex",
        name="Regex Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="bucket_name",
        regex_match=r"^[a-z0-9-]+$",
        message="Bucket name must be lowercase alphanumeric with hyphens only",
    )

    # Compliant resource
    resources_good = [
        {
            "address": "aws_s3_bucket.valid",
            "type": "aws_s3_bucket",
            "name": "valid",
            "values": {"bucket_name": "my-valid-bucket-123"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Non-compliant resource (uppercase)
    resources_bad = [
        {
            "address": "aws_s3_bucket.invalid",
            "type": "aws_s3_bucket",
            "name": "invalid",
            "values": {"bucket_name": "MyInvalidBucket"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1
    assert "matches pattern" in violations[0].message


def test_evaluator_regex_match_complex():
    """Test regex_match with more complex patterns."""
    evaluator = SimpleEvaluator()

    # Email validation pattern
    rule = Rule(
        id="test-email-regex",
        name="Email Regex Test",
        resource_type="aws_resource",
        severity="error",
        property="email",
        regex_match=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        message="Must be a valid email address",
    )

    # Valid email
    resources_good = [
        {
            "address": "aws_resource.valid",
            "type": "aws_resource",
            "name": "valid",
            "values": {"email": "user@example.com"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_good)
    assert len(violations) == 0

    # Invalid email
    resources_bad = [
        {
            "address": "aws_resource.invalid",
            "type": "aws_resource",
            "name": "invalid",
            "values": {"email": "not-an-email"},
        }
    ]

    violations = evaluator.evaluate(rule, resources_bad)
    assert len(violations) == 1

def test_evaluator_skips_cross_resource_rules():
    """Test that SimpleEvaluator skips pure cross-resource rules (no property)."""
    evaluator = SimpleEvaluator()

    # Pure cross-resource rule (no property field)
    rule = Rule(
        id="s3-requires-versioning",
        name="S3 buckets must have versioning",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
            )
        ],
        message="S3 bucket must have versioning",
    )

    resources = [
        {
            "address": "aws_s3_bucket.test",
            "type": "aws_s3_bucket",
            "name": "test",
            "values": {"bucket": "test"},
        }
    ]

    # Should return empty list (SimpleEvaluator skips cross-resource rules)
    violations = evaluator.evaluate(rule, resources)
    assert violations == []


def test_evaluator_only_on_create_filters_updates():
    """Test that only_on_create rules skip update actions."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        contains="Environment",
        message="Resource {{resource_name}} must have Environment tag",
        only_on_create=True,
    )

    resources = [
        {
            "address": "aws_s3_bucket.created",
            "type": "aws_s3_bucket",
            "name": "created",
            "values": {"bucket": "new-bucket"},  # Missing tags - should violate
            "actions": ["create"],
        },
        {
            "address": "aws_s3_bucket.updated",
            "type": "aws_s3_bucket",
            "name": "updated",
            "values": {"bucket": "existing-bucket"},  # Missing tags - should be skipped
            "actions": ["update"],
        },
    ]

    violations = evaluator.evaluate(rule, resources)

    # Should only find violation for the created resource
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_s3_bucket.created"


def test_evaluator_only_on_create_includes_replacements():
    """Test that only_on_create rules apply to replacement actions."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        contains="Environment",
        message="Resource {{resource_name}} must have Environment tag",
        only_on_create=True,
    )

    resources = [
        {
            "address": "aws_s3_bucket.replaced_standard",
            "type": "aws_s3_bucket",
            "name": "replaced_standard",
            "values": {"bucket": "replacement-bucket"},  # Missing tags
            "actions": ["delete", "create"],
        },
        {
            "address": "aws_s3_bucket.replaced_cbd",
            "type": "aws_s3_bucket",
            "name": "replaced_cbd",
            "values": {"bucket": "replacement-bucket-2"},  # Missing tags
            "actions": ["create", "delete"],
        },
    ]

    violations = evaluator.evaluate(rule, resources)

    # Should find violations for both replaced resources
    assert len(violations) == 2
    addresses = [v.resource_name for v in violations]
    assert "aws_s3_bucket.replaced_standard" in addresses
    assert "aws_s3_bucket.replaced_cbd" in addresses


def test_evaluator_without_only_on_create_evaluates_all():
    """Test that rules without only_on_create evaluate all resources."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        contains="Environment",
        message="Resource {{resource_name}} must have Environment tag",
        # only_on_create not set - should evaluate all
    )

    resources = [
        {
            "address": "aws_s3_bucket.created",
            "type": "aws_s3_bucket",
            "name": "created",
            "values": {"bucket": "new-bucket"},  # Missing tags
            "actions": ["create"],
        },
        {
            "address": "aws_s3_bucket.updated",
            "type": "aws_s3_bucket",
            "name": "updated",
            "values": {"bucket": "existing-bucket"},  # Missing tags
            "actions": ["update"],
        },
    ]

    violations = evaluator.evaluate(rule, resources)

    # Should find violations for BOTH resources
    assert len(violations) == 2


def test_evaluator_detect_destructive_actions_filters_creates():
    """Test that detect_destructive_actions rules skip create-only actions."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="critical-deletion",
        name="Critical resource being deleted",
        resource_type="aws_db_instance",
        severity="warning",
        resource_forbidden=True,
        detect_destructive_actions=True,
        message="Critical resource {{resource_name}} is being deleted or replaced",
    )

    resources = [
        {
            "address": "aws_db_instance.created",
            "type": "aws_db_instance",
            "name": "created",
            "values": {"identifier": "new-db"},
            "actions": ["create"],
        },
        {
            "address": "aws_db_instance.deleted",
            "type": "aws_db_instance",
            "name": "deleted",
            "values": {"identifier": "old-db"},
            "actions": ["delete"],
        },
    ]

    violations = evaluator.evaluate(rule, resources)

    # Should only find violation for the deleted resource
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_db_instance.deleted"


def test_evaluator_detect_destructive_actions_includes_replacements():
    """Test that detect_destructive_actions rules apply to replacement actions."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="critical-replacement",
        name="Critical resource being replaced",
        resource_type="aws_mwaa_environment",
        severity="warning",
        resource_forbidden=True,
        detect_destructive_actions=True,
        message="Critical resource {{resource_name}} is being deleted or replaced",
    )

    resources = [
        {
            "address": "aws_mwaa_environment.replaced_standard",
            "type": "aws_mwaa_environment",
            "name": "replaced_standard",
            "values": {"name": "airflow"},
            "actions": ["delete", "create"],
        },
        {
            "address": "aws_mwaa_environment.replaced_cbd",
            "type": "aws_mwaa_environment",
            "name": "replaced_cbd",
            "values": {"name": "airflow2"},
            "actions": ["create", "delete"],
        },
        {
            "address": "aws_mwaa_environment.updated",
            "type": "aws_mwaa_environment",
            "name": "updated",
            "values": {"name": "airflow3"},
            "actions": ["update"],
        },
    ]

    violations = evaluator.evaluate(rule, resources)

    # Should find violations for both replaced resources, but not the updated one
    assert len(violations) == 2
    addresses = [v.resource_name for v in violations]
    assert "aws_mwaa_environment.replaced_standard" in addresses
    assert "aws_mwaa_environment.replaced_cbd" in addresses


def test_evaluator_detect_destructive_actions_with_multiple_resource_types():
    """Test detect_destructive_actions with multiple resource types."""
    evaluator = SimpleEvaluator()

    rule = Rule(
        id="critical-destruction",
        name="Critical resources being destroyed",
        resource_types=["aws_db_instance", "aws_mwaa_environment", "aws_instance"],
        severity="warning",
        resource_forbidden=True,
        detect_destructive_actions=True,
        message="Critical resource {{resource_name}} is being deleted or replaced",
    )

    resources = [
        {
            "address": "aws_db_instance.deleted",
            "type": "aws_db_instance",
            "name": "deleted",
            "values": {"identifier": "db"},
            "actions": ["delete"],
        },
        {
            "address": "aws_mwaa_environment.replaced",
            "type": "aws_mwaa_environment",
            "name": "replaced",
            "values": {"name": "airflow"},
            "actions": ["delete", "create"],
        },
        {
            "address": "aws_instance.created",
            "type": "aws_instance",
            "name": "created",
            "values": {"id": "i-123"},
            "actions": ["create"],
        },
        {
            "address": "aws_s3_bucket.deleted",
            "type": "aws_s3_bucket",
            "name": "deleted",
            "values": {"bucket": "test"},
            "actions": ["delete"],
        },
    ]

    violations = evaluator.evaluate(rule, resources)

    # Should find violations for deleted DB and replaced MWAA, but not created instance or deleted S3
    assert len(violations) == 2
    addresses = [v.resource_name for v in violations]
    assert "aws_db_instance.deleted" in addresses
    assert "aws_mwaa_environment.replaced" in addresses
