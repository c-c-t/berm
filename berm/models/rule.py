"""Rule model for policy definitions."""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator, model_validator

from berm.security import validate_property_path


class RequiredResource(BaseModel):
    """Defines a required related resource in cross-resource validation rules.

    This model specifies that when a primary resource exists in a Terraform plan,
    certain related resources must also exist and optionally meet specific conditions.

    Example:
        For S3 buckets requiring versioning:
        {
            "resource_type": "aws_s3_bucket_versioning",
            "relationship": "referenced_by_primary",
            "reference_property": "bucket",
            "min_count": 1,
            "conditions": {
                "versioning_configuration.0.status": "Enabled"
            }
        }
    """

    resource_type: str = Field(
        ...,
        description="Type of required resource (e.g., 'aws_s3_bucket_versioning')",
        min_length=1,
    )

    relationship: Literal["references_primary", "referenced_by_primary", "same_name_suffix"] = Field(
        ...,
        description=(
            "How this resource relates to the primary resource:\n"
            "- 'references_primary': Primary resource references this resource\n"
            "- 'referenced_by_primary': This resource references the primary resource\n"
            "- 'same_name_suffix': Resources share the same name component"
        ),
    )

    reference_property: Optional[str] = Field(
        None,
        description=(
            "Property containing the reference (e.g., 'bucket' for S3 versioning). "
            "Required for 'references_primary' and 'referenced_by_primary' relationships."
        ),
        min_length=1,
    )

    min_count: int = Field(
        1,
        description="Minimum number of this resource type required (default: 1)",
        ge=0,
    )

    max_count: Optional[int] = Field(
        None,
        description="Maximum number of this resource type allowed (optional)",
        ge=1,
    )

    conditions: Optional[Dict[str, Any]] = Field(
        None,
        description=(
            "Additional property conditions the related resource must meet. "
            "Keys are dot-notation property paths, values are expected values."
        ),
    )

    message_suffix: Optional[str] = Field(
        None,
        description="Additional context to append to violation message",
        min_length=1,
    )

    @model_validator(mode="after")
    def validate_reference_property_required(self) -> "RequiredResource":
        """Ensure reference_property is specified for reference-based relationships."""
        if self.relationship in ("references_primary", "referenced_by_primary"):
            if self.reference_property is None:
                raise ValueError(
                    f"reference_property is required for '{self.relationship}' relationship"
                )
        return self

    @model_validator(mode="after")
    def validate_count_range(self) -> "RequiredResource":
        """Ensure max_count >= min_count if both specified."""
        if self.max_count is not None and self.max_count < self.min_count:
            raise ValueError(
                f"max_count ({self.max_count}) must be >= min_count ({self.min_count})"
            )
        return self


class Rule(BaseModel):
    """A policy rule that defines requirements for infrastructure resources.

    Rules are defined in JSON format and specify what properties resources
    must have to comply with organizational policies.

    Examples:
        Equality check:
        {
            "id": "s3-versioning-enabled",
            "name": "S3 buckets must have versioning enabled",
            "resource_type": "aws_s3_bucket",
            "severity": "error",
            "property": "versioning.enabled",
            "equals": true,
            "message": "S3 bucket {{resource_name}} must have versioning enabled"
        }

        Numeric comparison:
        {
            "id": "rds-backup-retention-minimum",
            "name": "RDS instances should have minimum backup retention",
            "resource_type": "aws_db_instance",
            "severity": "warning",
            "property": "backup_retention_period",
            "greater_than_or_equal": 7,
            "message": "RDS instance {{resource_name}} should have at least 7 days backup retention"
        }

        Forbidden resource (enforce module usage):
        {
            "id": "s3-use-module-only",
            "name": "S3 buckets must use approved module",
            "resource_type": "aws_s3_bucket",
            "severity": "error",
            "resource_forbidden": true,
            "message": "Direct use of aws_s3_bucket is not allowed. Use module.s3_bucket instead"
        }
    """

    id: str = Field(
        ...,
        description="Unique identifier for the rule",
        min_length=1,
    )

    name: str = Field(
        ...,
        description="Human-readable name for the rule",
        min_length=1,
    )

    resource_type: Optional[str] = Field(
        None,
        description="Terraform resource type to check (e.g., 'aws_s3_bucket'). Use resource_types for multiple types.",
        min_length=1,
    )

    resource_types: Optional[List[str]] = Field(
        None,
        description="List of Terraform resource types to check (alternative to resource_type)",
        min_length=1,
    )

    severity: Literal["error", "warning"] = Field(
        ...,
        description="Severity level: 'error' blocks deployment, 'warning' is advisory",
    )

    property: Optional[str] = Field(
        None,
        description="Dot-notation path to the property to check (e.g., 'versioning.enabled'). Not required for resource_forbidden rules.",
        min_length=1,
    )

    # Rule type: forbidden resource (blocks all usage of a resource type)
    resource_forbidden: Optional[bool] = Field(
        None,
        description="If true, any usage of this resource_type is a violation (for enforcing module usage)",
    )

    # Comparison operators (exactly one must be specified for property-based rules)
    equals: Optional[bool | str | int | float | None] = Field(
        None,
        description="Expected value that the property should equal",
    )

    greater_than: Optional[int | float] = Field(
        None,
        description="Property value must be greater than this number",
    )

    greater_than_or_equal: Optional[int | float] = Field(
        None,
        description="Property value must be greater than or equal to this number",
    )

    less_than: Optional[int | float] = Field(
        None,
        description="Property value must be less than this number",
    )

    less_than_or_equal: Optional[int | float] = Field(
        None,
        description="Property value must be less than or equal to this number",
    )

    contains: Optional[str] = Field(
        None,
        description="Property value (string or list) must contain this substring/element",
    )

    in_list: Optional[List[bool | str | int | float | None]] = Field(
        None,
        description="Property value must be one of the values in this list",
        alias="in",
    )

    regex_match: Optional[str] = Field(
        None,
        description="Property value must match this regular expression pattern",
    )

    has_keys: Optional[List[str]] = Field(
        None,
        description="Property value (dict) must contain all of these keys",
        min_length=1,
    )

    is_not_empty: Optional[bool] = Field(
        None,
        description="Property value must exist and not be empty (for dicts, lists, or strings)",
    )

    # Action-based filtering
    only_on_create: Optional[bool] = Field(
        None,
        description=(
            "If true, only evaluate this rule for resources being created "
            "(includes: ['create'], ['delete', 'create'], ['create', 'delete']). "
            "Resources being updated in-place will be skipped. "
            "Default: None (evaluate all resources)."
        ),
    )

    # Cross-resource relationship checking
    requires_resources: Optional[List[RequiredResource]] = Field(
        None,
        description=(
            "List of required related resources that must exist alongside this resource. "
            "Used for cross-resource validation (e.g., S3 bucket must have versioning resource)."
        ),
        min_length=1,
    )

    message: str = Field(
        ...,
        description="Error message to display when rule fails. Supports {{resource_name}} template.",
        min_length=1,
    )

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Ensure severity is either 'error' or 'warning'."""
        if v not in ("error", "warning"):
            raise ValueError(f"Severity must be 'error' or 'warning', got: {v}")
        return v

    @field_validator("property")
    @classmethod
    def validate_property_path_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate property path format for security."""
        if v is not None:
            try:
                validate_property_path(v)
            except Exception as e:
                raise ValueError(f"Invalid property path: {e}")
        return v

    @model_validator(mode="after")
    def validate_resource_type_exclusivity(self) -> "Rule":
        """Ensure either resource_type OR resource_types is specified, not both."""
        has_single = self.resource_type is not None
        has_multiple = self.resource_types is not None

        if not has_single and not has_multiple:
            raise ValueError(
                "Rule must specify either 'resource_type' (single) or 'resource_types' (multiple)"
            )

        if has_single and has_multiple:
            raise ValueError(
                "Rule cannot specify both 'resource_type' and 'resource_types'. Use one or the other."
            )

        # Validate resource_types list if provided
        if has_multiple:
            if len(self.resource_types) == 0:
                raise ValueError("resource_types must contain at least one resource type")

            # Check for duplicates
            if len(self.resource_types) != len(set(self.resource_types)):
                raise ValueError("resource_types contains duplicate entries")

        return self

    @model_validator(mode="after")
    def validate_comparison_operator(self) -> "Rule":
        """Ensure exactly one comparison operator is specified, or resource_forbidden is set, or requires_resources is set."""
        # Check if this is a forbidden resource rule
        if self.resource_forbidden is True:
            # For forbidden resources, property and operators are not needed
            if self.property is not None:
                raise ValueError(
                    "resource_forbidden rules should not specify a property"
                )
            # All comparison operators should be None
            if any([
                self.equals is not None,
                self.greater_than is not None,
                self.greater_than_or_equal is not None,
                self.less_than is not None,
                self.less_than_or_equal is not None,
                self.contains is not None,
                self.in_list is not None,
                self.regex_match is not None,
            ]):
                raise ValueError(
                    "resource_forbidden rules should not specify comparison operators"
                )
            # Cross-resource checks don't make sense with forbidden resources
            if self.requires_resources is not None:
                raise ValueError(
                    "resource_forbidden rules cannot specify requires_resources"
                )
            return self

        # Check if this is a cross-resource rule (only requires_resources, no property checks)
        if self.requires_resources is not None and len(self.requires_resources) > 0:
            # Cross-resource rules can optionally have property checks, but don't require them
            # If no property is specified, we're doing pure cross-resource validation
            if self.property is None:
                # Ensure no comparison operators are specified
                if any([
                    self.equals is not None,
                    self.greater_than is not None,
                    self.greater_than_or_equal is not None,
                    self.less_than is not None,
                    self.less_than_or_equal is not None,
                    self.contains is not None,
                    self.in_list is not None,
                    self.regex_match is not None,
                    self.has_keys is not None,
                    self.is_not_empty is not None,
                ]):
                    raise ValueError(
                        "Cross-resource rules without property should not specify comparison operators"
                    )
                return self
            # If property is specified, fall through to normal validation

        # For property-based rules, ensure property is specified
        if self.property is None:
            raise ValueError(
                "Rules must specify either a property to check, resource_forbidden, or requires_resources"
            )

        # Count non-None operators (note: equals can be None as a valid value)
        specified = [
            op for op in [
                self.equals is not None,
                self.greater_than is not None,
                self.greater_than_or_equal is not None,
                self.less_than is not None,
                self.less_than_or_equal is not None,
                self.contains is not None,
                self.in_list is not None,
                self.regex_match is not None,
                self.has_keys is not None,
                self.is_not_empty is not None,
            ] if op
        ]

        if len(specified) == 0:
            raise ValueError(
                "Rule must specify exactly one comparison operator: "
                "equals, greater_than, greater_than_or_equal, less_than, less_than_or_equal, "
                "contains, in, regex_match, has_keys, or is_not_empty"
            )

        if len(specified) > 1:
            raise ValueError(
                "Rule must specify only one comparison operator, found multiple"
            )

        return self

    def format_message(self, resource_name: str, output_context: str = "terminal") -> str:
        """Format the rule message with resource context.

        Args:
            resource_name: Name of the resource that violated the rule
            output_context: Output context for sanitization ("terminal", "github", "json")

        Returns:
            Formatted message with template variables replaced and sanitized
        """
        from berm.security import sanitize_for_output

        # Sanitize resource name to prevent injection attacks
        safe_resource_name = sanitize_for_output(resource_name, context=output_context)

        return self.message.replace("{{resource_name}}", safe_resource_name)

    def __str__(self) -> str:
        """String representation of the rule."""
        return f"Rule({self.id}: {self.name})"

    def __repr__(self) -> str:
        """Detailed representation of the rule."""
        return (
            f"Rule(id='{self.id}', name='{self.name}', "
            f"resource_type='{self.resource_type}', severity='{self.severity}')"
        )

    def matches_resource_type(self, resource_type: str) -> bool:
        """Check if this rule applies to the given resource type.

        Args:
            resource_type: Resource type to check (e.g., 'aws_s3_bucket')

        Returns:
            True if rule applies to this resource type
        """
        if self.resource_type is not None:
            return resource_type == self.resource_type
        elif self.resource_types is not None:
            return resource_type in self.resource_types
        return False

    def is_creation_action(self, actions: List[str]) -> bool:
        """Check if the given actions represent resource creation.

        Creation includes:
        - ["create"] - new resource
        - ["delete", "create"] - standard replacement
        - ["create", "delete"] - create_before_destroy replacement

        Args:
            actions: List of Terraform actions for the resource

        Returns:
            True if actions represent creation, False otherwise
        """
        if not actions:
            return False

        # Pure creation
        if actions == ["create"]:
            return True

        # Replacement (both orderings)
        if set(actions) == {"create", "delete"}:
            return True

        return False
