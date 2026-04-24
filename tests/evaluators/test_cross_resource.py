"""Tests for CrossResourceEvaluator."""

import pytest

from berm.evaluators.cross_resource import CrossResourceEvaluator
from berm.models.rule import RequiredResource, Rule


@pytest.fixture
def evaluator():
    """Create a CrossResourceEvaluator instance."""
    return CrossResourceEvaluator()


@pytest.fixture
def s3_bucket_resources():
    """Sample S3 bucket resources with versioning (compliant)."""
    return [
        {
            "address": "aws_s3_bucket.compliant",
            "type": "aws_s3_bucket",
            "name": "compliant",
            "values": {"bucket": "my-bucket-123"},
        },
        {
            "address": "aws_s3_bucket_versioning.compliant",
            "type": "aws_s3_bucket_versioning",
            "name": "compliant",
            "values": {
                "versioning_configuration": [{"status": "Enabled"}]
            },
        },
        {
            "address": "aws_s3_bucket.non_compliant",
            "type": "aws_s3_bucket",
            "name": "non_compliant",
            "values": {"bucket": "my-other-bucket-456"},
        },
    ]


@pytest.fixture
def s3_plan_with_references():
    """Terraform plan data with reference information."""
    return {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.compliant",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket-123"}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_versioning.compliant",
                        "expressions": {
                            "bucket": {
                                "references": ["aws_s3_bucket.compliant.id", "aws_s3_bucket.compliant"]
                            }
                        }
                    },
                    {
                        "address": "aws_s3_bucket.non_compliant",
                        "expressions": {
                            "bucket": {"constant_value": "my-other-bucket-456"}
                        }
                    }
                ]
            }
        }
    }


@pytest.fixture
def s3_plan_with_static_values():
    """Terraform plan with static/hardcoded bucket names."""
    return {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.compliant",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket-123"}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_versioning.compliant",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket-123"}
                        }
                    },
                    {
                        "address": "aws_s3_bucket.non_compliant",
                        "expressions": {
                            "bucket": {"constant_value": "my-other-bucket-456"}
                        }
                    }
                ]
            }
        }
    }


def test_evaluate_with_dynamic_references(evaluator, s3_bucket_resources, s3_plan_with_references):
    """Test evaluation with dynamic Terraform references."""
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
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    violations = evaluator.evaluate(rule, s3_bucket_resources, s3_plan_with_references)

    # Should find 1 violation: non_compliant bucket missing versioning
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_s3_bucket.non_compliant"
    assert "Missing required aws_s3_bucket_versioning" in violations[0].message


def test_evaluate_with_static_values(evaluator, s3_bucket_resources, s3_plan_with_static_values):
    """Test evaluation with static/hardcoded bucket names."""
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
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    violations = evaluator.evaluate(rule, s3_bucket_resources, s3_plan_with_static_values)

    # Should find 1 violation: non_compliant bucket missing versioning
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_s3_bucket.non_compliant"


def test_evaluate_with_name_based_matching(evaluator, s3_bucket_resources):
    """Test evaluation with name-based matching (no plan data)."""
    rule = Rule(
        id="s3-requires-versioning",
        name="S3 buckets must have versioning",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="same_name_suffix",
                min_count=1,
            )
        ],
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    # Pass no plan_data, should fall back to name matching
    violations = evaluator.evaluate(rule, s3_bucket_resources, None)

    # Should find 1 violation: non_compliant bucket (different name)
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_s3_bucket.non_compliant"


def test_evaluate_with_conditions(evaluator):
    """Test evaluation with property conditions on related resources."""
    resources = [
        {
            "address": "aws_s3_bucket.test",
            "type": "aws_s3_bucket",
            "name": "test",
            "values": {"bucket": "test-bucket"},
        },
        {
            "address": "aws_s3_bucket_versioning.test_disabled",
            "type": "aws_s3_bucket_versioning",
            "name": "test",
            "values": {
                "versioning_configuration": [{"status": "Disabled"}]
            },
        },
    ]

    rule = Rule(
        id="s3-versioning-enabled",
        name="S3 buckets must have versioning enabled",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="same_name_suffix",
                min_count=1,
                conditions={
                    "versioning_configuration.0.status": "Enabled"
                },
            )
        ],
        message="S3 bucket {{resource_name}} must have versioning enabled",
    )

    violations = evaluator.evaluate(rule, resources, None)

    # Should find 1 violation: versioning exists but status is Disabled
    assert len(violations) == 1
    assert "fails condition" in violations[0].message
    assert "Disabled" in violations[0].message
    assert "Enabled" in violations[0].message


def test_evaluate_multiple_required_resources(evaluator):
    """Test rule with multiple required resources."""
    resources = [
        {
            "address": "aws_s3_bucket.test",
            "type": "aws_s3_bucket",
            "name": "test",
            "values": {"bucket": "test-bucket"},
        },
        {
            "address": "aws_s3_bucket_versioning.test",
            "type": "aws_s3_bucket_versioning",
            "name": "test",
            "values": {"versioning_configuration": [{"status": "Enabled"}]},
        },
        # Missing: aws_s3_bucket_public_access_block
    ]

    rule = Rule(
        id="s3-security",
        name="S3 buckets must have full security",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="same_name_suffix",
                min_count=1,
            ),
            RequiredResource(
                resource_type="aws_s3_bucket_public_access_block",
                relationship="same_name_suffix",
                min_count=1,
            ),
        ],
        message="S3 bucket {{resource_name}} must have complete security",
    )

    violations = evaluator.evaluate(rule, resources, None)

    # Should find 1 violation: missing public_access_block
    assert len(violations) == 1
    assert "aws_s3_bucket_public_access_block" in violations[0].message


def test_evaluate_min_max_count_violations(evaluator):
    """Test min_count and max_count requirements."""
    resources = [
        {
            "address": "aws_lb.main",
            "type": "aws_lb",
            "name": "main",
            "values": {},
        },
        {
            "address": "aws_lb_listener.http",
            "type": "aws_lb_listener",
            "name": "main",
            "values": {"protocol": "HTTP"},
        },
        {
            "address": "aws_lb_listener.https",
            "type": "aws_lb_listener",
            "name": "main",
            "values": {"protocol": "HTTPS"},
        },
        {
            "address": "aws_lb_listener.extra",
            "type": "aws_lb_listener",
            "name": "main",
            "values": {"protocol": "HTTPS"},
        },
    ]

    # Rule requiring exactly 1-2 listeners
    rule = Rule(
        id="lb-listener-limit",
        name="Load balancer must have 1-2 listeners",
        resource_type="aws_lb",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_lb_listener",
                relationship="same_name_suffix",
                min_count=1,
                max_count=2,
            )
        ],
        message="Load balancer {{resource_name}} has incorrect number of listeners",
    )

    violations = evaluator.evaluate(rule, resources, None)

    # Should find 1 violation: too many listeners (3 > 2)
    assert len(violations) == 1
    assert "Too many" in violations[0].message
    assert "max 2" in violations[0].message


def test_evaluate_no_violations_when_compliant(evaluator, s3_bucket_resources, s3_plan_with_references):
    """Test that no violations are returned when resources are compliant."""
    # Add the missing versioning resource for non_compliant bucket
    compliant_resources = s3_bucket_resources + [
        {
            "address": "aws_s3_bucket_versioning.non_compliant",
            "type": "aws_s3_bucket_versioning",
            "name": "non_compliant",
            "values": {"versioning_configuration": [{"status": "Enabled"}]},
        }
    ]

    # Update plan data
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": s3_plan_with_references["configuration"]["root_module"]["resources"] + [
                    {
                        "address": "aws_s3_bucket_versioning.non_compliant",
                        "expressions": {
                            "bucket": {
                                "references": ["aws_s3_bucket.non_compliant.id"]
                            }
                        }
                    }
                ]
            }
        }
    }

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
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    violations = evaluator.evaluate(rule, compliant_resources, plan_data)

    # Should find no violations
    assert len(violations) == 0


def test_evaluate_skips_non_cross_resource_rules(evaluator, s3_bucket_resources):
    """Test that evaluator skips rules without requires_resources."""
    rule = Rule(
        id="s3-versioning",
        name="S3 versioning check",
        resource_type="aws_s3_bucket",
        severity="error",
        property="versioning.enabled",
        equals=True,
        message="Bucket must have versioning",
    )

    violations = evaluator.evaluate(rule, s3_bucket_resources, None)

    # Should return empty list (not a cross-resource rule)
    assert violations == []


def test_evaluate_with_message_suffix(evaluator):
    """Test that message_suffix is included in violation messages."""
    resources = [
        {
            "address": "aws_s3_bucket.test",
            "type": "aws_s3_bucket",
            "name": "test",
            "values": {"bucket": "test"},
        },
    ]

    rule = Rule(
        id="s3-security",
        name="S3 security requirements",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="same_name_suffix",
                min_count=1,
                message_suffix="with versioning enabled",
            )
        ],
        message="S3 bucket {{resource_name}} missing security",
    )

    violations = evaluator.evaluate(rule, resources, None)

    assert len(violations) == 1
    assert "with versioning enabled" in violations[0].message


def test_evaluate_resource_types_array(evaluator):
    """Test evaluation with multiple primary resource types."""
    resources = [
        {
            "address": "aws_s3_bucket.bucket1",
            "type": "aws_s3_bucket",
            "name": "bucket1",
            "values": {"bucket": "bucket1"},
        },
        {
            "address": "aws_s3_bucket_analytics_configuration.analytics1",
            "type": "aws_s3_bucket_analytics_configuration",
            "name": "analytics1",
            "values": {"bucket": "bucket1"},
        },
        # bucket1 has analytics, bucket2 does not
        {
            "address": "aws_s3_bucket.bucket2",
            "type": "aws_s3_bucket",
            "name": "bucket2",
            "values": {"bucket": "bucket2"},
        },
        {
            "address": "aws_s3_bucket_analytics_configuration.analytics2",
            "type": "aws_s3_bucket_analytics_configuration",
            "name": "bucket2",
            "values": {"bucket": "bucket2"},
        },
    ]

    # Rule applying to both regular buckets and analytics configs
    rule = Rule(
        id="s3-types-test",
        name="S3 resource test",
        resource_types=["aws_s3_bucket", "aws_s3_bucket_analytics_configuration"],
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="same_name_suffix",
                min_count=1,
            )
        ],
        message="Resource {{resource_name}} needs versioning",
    )

    violations = evaluator.evaluate(rule, resources, None)

    # Should find 4 violations (2 buckets + 2 analytics, all missing versioning)
    assert len(violations) == 4


def test_cross_resource_only_on_create_filters_updates():
    """Test that only_on_create works with cross-resource rules."""
    evaluator = CrossResourceEvaluator()

    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        message="S3 bucket {{resource_name}} must have versioning",
        only_on_create=True,
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
            )
        ],
    )

    resources = [
        {
            "address": "aws_s3_bucket.created",
            "type": "aws_s3_bucket",
            "name": "created",
            "values": {"bucket": "new-bucket"},
            "actions": ["create"],
        },
        {
            "address": "aws_s3_bucket.updated",
            "type": "aws_s3_bucket",
            "name": "updated",
            "values": {"bucket": "existing-bucket"},
            "actions": ["update"],
        },
    ]

    # No versioning resources exist for either
    violations = evaluator.evaluate(rule, resources, plan_data=None)

    # Should only find violation for created bucket, not updated one
    assert len(violations) == 1
    assert violations[0].resource_name == "aws_s3_bucket.created"


def test_evaluate_module_resources_with_references():
    """Test that cross-resource evaluation works for resources in submodules."""
    evaluator = CrossResourceEvaluator()

    # Resources from a submodule
    resources = [
        {
            "address": "module.s3_module.aws_s3_bucket.example",
            "type": "aws_s3_bucket",
            "name": "example",
            "values": {"bucket": "my-module-bucket"},
        },
        {
            "address": "module.s3_module.aws_s3_bucket_versioning.example",
            "type": "aws_s3_bucket_versioning",
            "name": "example",
            "values": {
                "bucket": "my-module-bucket",
                "versioning_configuration": [{"status": "Enabled"}],
            },
        },
        {
            "address": "module.s3_module.aws_s3_bucket.no_versioning",
            "type": "aws_s3_bucket",
            "name": "no_versioning",
            "values": {"bucket": "my-other-bucket"},
        },
    ]

    # Plan data with module resources
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "address": "module.s3_module",
                        "resources": [
                            {
                                "address": "module.s3_module.aws_s3_bucket.example",
                                "expressions": {
                                    "bucket": {"constant_value": "my-module-bucket"}
                                }
                            },
                            {
                                "address": "module.s3_module.aws_s3_bucket_versioning.example",
                                "expressions": {
                                    "bucket": {
                                        "references": ["module.s3_module.aws_s3_bucket.example.id"]
                                    }
                                }
                            },
                            {
                                "address": "module.s3_module.aws_s3_bucket.no_versioning",
                                "expressions": {
                                    "bucket": {"constant_value": "my-other-bucket"}
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }

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
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    violations = evaluator.evaluate(rule, resources, plan_data)

    # Should find 1 violation: no_versioning bucket missing versioning
    assert len(violations) == 1
    assert violations[0].resource_name == "module.s3_module.aws_s3_bucket.no_versioning"
    assert "Missing required aws_s3_bucket_versioning" in violations[0].message


def test_evaluate_module_resources_with_static_values():
    """Test that cross-resource evaluation works for module resources with static bucket names."""
    evaluator = CrossResourceEvaluator()

    # Resources from a submodule using hardcoded bucket names
    resources = [
        {
            "address": "module.s3_module.aws_s3_bucket.example",
            "type": "aws_s3_bucket",
            "name": "example",
            "values": {"bucket": "hardcoded-bucket-name"},
        },
        {
            "address": "module.s3_module.aws_s3_bucket_versioning.example",
            "type": "aws_s3_bucket_versioning",
            "name": "example",
            "values": {
                "bucket": "hardcoded-bucket-name",
                "versioning_configuration": [{"status": "Enabled"}],
            },
        },
    ]

    # Plan data with static constant values in child module
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "address": "module.s3_module",
                        "resources": [
                            {
                                "address": "module.s3_module.aws_s3_bucket.example",
                                "expressions": {
                                    "bucket": {"constant_value": "hardcoded-bucket-name"}
                                }
                            },
                            {
                                "address": "module.s3_module.aws_s3_bucket_versioning.example",
                                "expressions": {
                                    "bucket": {"constant_value": "hardcoded-bucket-name"}
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }

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
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    violations = evaluator.evaluate(rule, resources, plan_data)

    # Should find no violations - versioning resource exists with matching bucket name
    assert len(violations) == 0
