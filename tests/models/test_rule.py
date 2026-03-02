"""Tests for Rule model."""

import pytest
from pydantic import ValidationError

from berm.models.rule import RequiredResource, Rule


def test_rule_creation_valid():
    """Test creating a valid rule."""
    rule = Rule(
        id="test-rule",
        name="Test Rule",
        resource_type="aws_s3_bucket",
        severity="error",
        property="versioning.enabled",
        equals=True,
        message="Test message",
    )

    assert rule.id == "test-rule"
    assert rule.name == "Test Rule"
    assert rule.resource_type == "aws_s3_bucket"
    assert rule.severity == "error"
    assert rule.property == "versioning.enabled"
    assert rule.equals is True
    assert rule.message == "Test message"


def test_rule_severity_validation():
    """Test that severity must be 'error' or 'warning'."""
    # Valid severities
    rule_error = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=True,
        message="msg",
    )
    assert rule_error.severity == "error"

    rule_warning = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="warning",
        property="prop",
        equals=True,
        message="msg",
    )
    assert rule_warning.severity == "warning"

    # Invalid severity
    with pytest.raises(ValidationError):
        Rule(
            id="test",
            name="Test",
            resource_type="aws_s3_bucket",
            severity="invalid",
            property="prop",
            equals=True,
            message="msg",
        )


def test_rule_required_fields():
    """Test that all required fields must be provided."""
    with pytest.raises(ValidationError):
        Rule()


def test_rule_format_message():
    """Test message formatting with resource name."""
    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=True,
        message="Resource {{resource_name}} failed validation",
    )

    formatted = rule.format_message("aws_s3_bucket.example")
    assert formatted == "Resource aws_s3_bucket.example failed validation"


def test_rule_equals_types():
    """Test that equals can be various types."""
    # Boolean
    rule_bool = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=True,
        message="msg",
    )
    assert rule_bool.equals is True

    # String
    rule_str = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals="value",
        message="msg",
    )
    assert rule_str.equals == "value"

    # Integer
    rule_int = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=42,
        message="msg",
    )
    assert rule_int.equals == 42

    # Float
    rule_float = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=3.14,
        message="msg",
    )
    assert rule_float.equals == 3.14


def test_rule_string_representation():
    """Test string representations of rule."""
    rule = Rule(
        id="test-rule",
        name="Test Rule",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=True,
        message="msg",
    )

    assert "test-rule" in str(rule)
    assert "Test Rule" in str(rule)
    assert "test-rule" in repr(rule)


def test_rule_with_resource_types_array():
    """Test creating a rule with multiple resource types."""
    rule = Rule(
        id="multi-type-rule",
        name="Multi Type Rule",
        resource_types=["aws_s3_bucket", "aws_db_instance", "aws_lambda_function"],
        severity="error",
        property="tags",
        has_keys=["Environment", "Owner"],
        message="Resource {{resource_name}} must have required tags",
    )

    assert rule.resource_types == ["aws_s3_bucket", "aws_db_instance", "aws_lambda_function"]
    assert rule.resource_type is None
    assert rule.has_keys == ["Environment", "Owner"]


def test_rule_resource_type_mutual_exclusivity():
    """Test that resource_type and resource_types cannot both be specified."""
    with pytest.raises(ValidationError, match="cannot specify both"):
        Rule(
            id="invalid",
            name="Invalid",
            resource_type="aws_s3_bucket",
            resource_types=["aws_db_instance"],
            severity="error",
            property="prop",
            equals=True,
            message="msg",
        )


def test_rule_resource_type_required():
    """Test that either resource_type or resource_types must be specified."""
    with pytest.raises(ValidationError, match="must specify either"):
        Rule(
            id="invalid",
            name="Invalid",
            severity="error",
            property="prop",
            equals=True,
            message="msg",
        )


def test_rule_resource_types_empty_list():
    """Test that resource_types cannot be empty."""
    with pytest.raises(ValidationError, match="at least 1 item"):
        Rule(
            id="invalid",
            name="Invalid",
            resource_types=[],
            severity="error",
            property="prop",
            equals=True,
            message="msg",
        )


def test_rule_resource_types_duplicates():
    """Test that resource_types cannot contain duplicates."""
    with pytest.raises(ValidationError, match="duplicate"):
        Rule(
            id="invalid",
            name="Invalid",
            resource_types=["aws_s3_bucket", "aws_s3_bucket"],
            severity="error",
            property="prop",
            equals=True,
            message="msg",
        )


def test_rule_has_keys_operator():
    """Test rule with has_keys operator."""
    rule = Rule(
        id="test-has-keys",
        name="Has Keys Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        has_keys=["Environment", "Owner", "CostCenter"],
        message="Resource must have required tag keys",
    )

    assert rule.has_keys == ["Environment", "Owner", "CostCenter"]
    assert rule.equals is None


def test_rule_is_not_empty_operator():
    """Test rule with is_not_empty operator."""
    rule = Rule(
        id="test-not-empty",
        name="Not Empty Test",
        resource_type="aws_s3_bucket",
        severity="warning",
        property="tags",
        is_not_empty=True,
        message="Resource should have tags",
    )

    assert rule.is_not_empty is True
    assert rule.equals is None


def test_rule_multiple_operators_with_new_ones():
    """Test that only one operator can be specified including new ones."""
    with pytest.raises(ValidationError, match="only one comparison operator"):
        Rule(
            id="invalid",
            name="Invalid",
            resource_type="aws_s3_bucket",
            severity="error",
            property="prop",
            equals=True,
            has_keys=["key1"],
            message="msg",
        )


def test_rule_matches_resource_type_single():
    """Test matches_resource_type helper with single resource_type."""
    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=True,
        message="msg",
    )

    assert rule.matches_resource_type("aws_s3_bucket") is True
    assert rule.matches_resource_type("aws_db_instance") is False


def test_rule_matches_resource_type_multiple():
    """Test matches_resource_type helper with multiple resource_types."""
    rule = Rule(
        id="test",
        name="Test",
        resource_types=["aws_s3_bucket", "aws_db_instance", "aws_lambda_function"],
        severity="error",
        property="prop",
        equals=True,
        message="msg",
    )

    assert rule.matches_resource_type("aws_s3_bucket") is True
    assert rule.matches_resource_type("aws_db_instance") is True
    assert rule.matches_resource_type("aws_lambda_function") is True
    assert rule.matches_resource_type("aws_instance") is False


# Tests for RequiredResource model


def test_required_resource_creation_valid():
    """Test creating a valid RequiredResource."""
    req = RequiredResource(
        resource_type="aws_s3_bucket_versioning",
        relationship="referenced_by_primary",
        reference_property="bucket",
        min_count=1,
    )

    assert req.resource_type == "aws_s3_bucket_versioning"
    assert req.relationship == "referenced_by_primary"
    assert req.reference_property == "bucket"
    assert req.min_count == 1
    assert req.max_count is None
    assert req.conditions is None
    assert req.message_suffix is None


def test_required_resource_with_conditions():
    """Test RequiredResource with conditions."""
    req = RequiredResource(
        resource_type="aws_s3_bucket_versioning",
        relationship="referenced_by_primary",
        reference_property="bucket",
        min_count=1,
        conditions={"versioning_configuration.0.status": "Enabled"},
        message_suffix="with versioning enabled",
    )

    assert req.conditions == {"versioning_configuration.0.status": "Enabled"}
    assert req.message_suffix == "with versioning enabled"


def test_required_resource_requires_reference_property():
    """Test that reference_property is required for reference-based relationships."""
    # Should fail for referenced_by_primary without reference_property
    with pytest.raises(ValidationError, match="reference_property is required"):
        RequiredResource(
            resource_type="aws_s3_bucket_versioning",
            relationship="referenced_by_primary",
        )

    # Should fail for references_primary without reference_property
    with pytest.raises(ValidationError, match="reference_property is required"):
        RequiredResource(
            resource_type="aws_lb",
            relationship="references_primary",
        )

    # Should succeed for same_name_suffix without reference_property
    req = RequiredResource(
        resource_type="aws_s3_bucket_versioning",
        relationship="same_name_suffix",
    )
    assert req.reference_property is None


def test_required_resource_count_validation():
    """Test that max_count must be >= min_count."""
    # Valid: max > min
    req1 = RequiredResource(
        resource_type="aws_lb_listener",
        relationship="references_primary",
        reference_property="load_balancer_arn",
        min_count=1,
        max_count=5,
    )
    assert req1.max_count == 5

    # Valid: max == min
    req2 = RequiredResource(
        resource_type="aws_lb_listener",
        relationship="references_primary",
        reference_property="load_balancer_arn",
        min_count=1,
        max_count=1,
    )
    assert req2.max_count == 1

    # Invalid: max < min
    with pytest.raises(ValidationError, match="max_count.*must be >= min_count"):
        RequiredResource(
            resource_type="aws_lb_listener",
            relationship="references_primary",
            reference_property="load_balancer_arn",
            min_count=5,
            max_count=2,
        )


# Tests for cross-resource rules


def test_rule_with_requires_resources():
    """Test creating a rule with requires_resources (pure cross-resource validation)."""
    rule = Rule(
        id="s3-bucket-requires-versioning",
        name="S3 buckets must have versioning configured",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
                conditions={"versioning_configuration.0.status": "Enabled"},
            )
        ],
        message="S3 bucket {{resource_name}} must have versioning configured",
    )

    assert rule.requires_resources is not None
    assert len(rule.requires_resources) == 1
    assert rule.requires_resources[0].resource_type == "aws_s3_bucket_versioning"
    assert rule.property is None  # Pure cross-resource rule, no property check


def test_rule_with_both_property_and_requires_resources():
    """Test rule that combines property check with cross-resource validation."""
    rule = Rule(
        id="s3-secure-bucket",
        name="S3 buckets must be encrypted and have versioning",
        resource_type="aws_s3_bucket",
        severity="error",
        property="server_side_encryption_configuration.0.rule.0.apply_server_side_encryption_by_default.0.sse_algorithm",
        equals="AES256",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
            )
        ],
        message="S3 bucket {{resource_name}} must be encrypted and have versioning",
    )

    assert rule.property is not None
    assert rule.equals == "AES256"
    assert rule.requires_resources is not None
    assert len(rule.requires_resources) == 1


def test_rule_cross_resource_without_operators():
    """Test that pure cross-resource rules cannot have comparison operators."""
    # Should fail if we specify requires_resources but also a comparison operator without property
    with pytest.raises(ValidationError, match="should not specify comparison operators"):
        Rule(
            id="test",
            name="Test",
            resource_type="aws_s3_bucket",
            severity="error",
            requires_resources=[
                RequiredResource(
                    resource_type="aws_s3_bucket_versioning",
                    relationship="referenced_by_primary",
                    reference_property="bucket",
                )
            ],
            equals=True,  # Invalid: no property but has operator
            message="msg",
        )


def test_rule_forbidden_resource_cannot_have_requires_resources():
    """Test that resource_forbidden rules cannot have requires_resources."""
    with pytest.raises(ValidationError, match="resource_forbidden rules cannot specify requires_resources"):
        Rule(
            id="test",
            name="Test",
            resource_type="aws_s3_bucket",
            severity="error",
            resource_forbidden=True,
            requires_resources=[
                RequiredResource(
                    resource_type="aws_s3_bucket_versioning",
                    relationship="referenced_by_primary",
                    reference_property="bucket",
                )
            ],
            message="msg",
        )


def test_rule_multiple_required_resources():
    """Test rule with multiple required resources."""
    rule = Rule(
        id="s3-bucket-security",
        name="S3 buckets must have full security configuration",
        resource_type="aws_s3_bucket",
        severity="error",
        requires_resources=[
            RequiredResource(
                resource_type="aws_s3_bucket_versioning",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
            ),
            RequiredResource(
                resource_type="aws_s3_bucket_public_access_block",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
            ),
            RequiredResource(
                resource_type="aws_s3_bucket_server_side_encryption_configuration",
                relationship="referenced_by_primary",
                reference_property="bucket",
                min_count=1,
            ),
        ],
        message="S3 bucket {{resource_name}} must have complete security configuration",
    )

    assert len(rule.requires_resources) == 3
    assert rule.requires_resources[0].resource_type == "aws_s3_bucket_versioning"
    assert rule.requires_resources[1].resource_type == "aws_s3_bucket_public_access_block"
    assert rule.requires_resources[2].resource_type == "aws_s3_bucket_server_side_encryption_configuration"


def test_rule_only_on_create_valid():
    """Test creating a rule with only_on_create field."""
    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        contains="Environment",
        message="msg",
        only_on_create=True,
    )

    assert rule.only_on_create is True


def test_rule_only_on_create_optional():
    """Test that only_on_create is optional and defaults to None."""
    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="tags",
        contains="Environment",
        message="msg",
    )

    assert rule.only_on_create is None


def test_rule_is_creation_action():
    """Test the is_creation_action helper method."""
    rule = Rule(
        id="test",
        name="Test",
        resource_type="aws_s3_bucket",
        severity="error",
        property="prop",
        equals=True,
        message="msg",
    )

    # Creation actions
    assert rule.is_creation_action(["create"]) is True
    assert rule.is_creation_action(["delete", "create"]) is True
    assert rule.is_creation_action(["create", "delete"]) is True

    # Non-creation actions
    assert rule.is_creation_action(["update"]) is False
    assert rule.is_creation_action([]) is False
    assert rule.is_creation_action(["delete"]) is False
    assert rule.is_creation_action(["no-op"]) is False
