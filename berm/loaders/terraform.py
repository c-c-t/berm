"""Loader for Terraform plan JSON files."""

import json
from typing import Any, Dict, List

from berm.security import (
    ALLOWED_PLAN_EXTENSIONS,
    MAX_ARRAY_INDEX,
    SecurityError,
    validate_file_size,
    validate_json_depth,
    validate_safe_path,
)


class TerraformPlanLoadError(Exception):
    """Exception raised when Terraform plan loading fails."""

    pass


def load_terraform_plan(plan_path: str, _allow_absolute: bool = False) -> List[Dict[str, Any]]:
    """Load and parse a Terraform plan JSON file.

    Extracts resource changes from the plan and normalizes them for evaluation.
    Only includes resources that are being created, updated, or replaced.
    Excludes resources that are being deleted or unchanged (no-op).

    Args:
        plan_path: Path to Terraform plan JSON file (output of 'terraform show -json')
        _allow_absolute: Internal parameter for testing - allows absolute paths

    Returns:
        List of resource dictionaries with normalized structure:
        [
            {
                "address": "aws_s3_bucket.example",
                "type": "aws_s3_bucket",
                "name": "example",
                "values": {...},  # Resource configuration
                "actions": ["create"] | ["update"] | ["delete", "create"] | ["create", "delete"]
            },
            ...
        ]

    Raises:
        TerraformPlanLoadError: If file doesn't exist, isn't valid JSON,
                               or doesn't have expected structure
    """
    # Validate and sanitize the path (prevents path traversal, checks file size)
    try:
        path = validate_safe_path(
            plan_path,
            must_exist=True,
            allowed_extensions=ALLOWED_PLAN_EXTENSIONS,
            allow_absolute=_allow_absolute,
        )
        validate_file_size(path)
    except (SecurityError, ValueError) as e:
        raise TerraformPlanLoadError(f"Security validation failed: {e}")

    # Load and parse JSON
    try:
        # Use utf-8-sig to handle UTF-8 BOM if present (common in Windows)
        with open(path, "r", encoding="utf-8-sig") as f:
            plan_data = json.load(f)

        # Validate JSON depth to prevent DoS via deeply nested structures
        validate_json_depth(plan_data)
    except json.JSONDecodeError as e:
        raise TerraformPlanLoadError(f"Invalid JSON in plan file: {e}")
    except SecurityError as e:
        raise TerraformPlanLoadError(f"Security validation failed: {e}")
    except Exception as e:
        raise TerraformPlanLoadError(f"Error reading plan file: {e}")

    # Validate plan structure
    if not isinstance(plan_data, dict):
        raise TerraformPlanLoadError("Plan file must contain a JSON object")

    # Extract resource_changes
    resource_changes = plan_data.get("resource_changes", [])

    if not isinstance(resource_changes, list):
        raise TerraformPlanLoadError(
            "Plan file 'resource_changes' must be a list"
        )

    # Normalize resources
    resources = []

    for change in resource_changes:
        try:
            # Skip if not a valid resource change
            if not isinstance(change, dict):
                continue

            # Get action type
            actions = change.get("change", {}).get("actions", [])

            # Skip resources being deleted or no-op
            if not actions or actions == ["delete"] or actions == ["no-op"]:
                continue

            # Extract resource details
            address = change.get("address", "")
            resource_type = change.get("type", "")
            name = change.get("name", "")

            # Get the 'after' values (planned configuration)
            # For creates, this is in 'after'
            # For updates, 'after' contains the new values
            values = change.get("change", {}).get("after", {})

            # If 'after' is None, try 'after_unknown' or 'before'
            if values is None:
                values = change.get("change", {}).get("before", {})

            if values is None:
                values = {}

            # Build normalized resource
            resource = {
                "address": address,
                "type": resource_type,
                "name": name,
                "values": values,
                "actions": actions,
            }

            resources.append(resource)

        except Exception as e:
            # Log warning but continue processing other resources
            # In production, might want proper logging here
            continue

    return resources


def get_resource_by_type(
    resources: List[Dict[str, Any]], resource_type: str
) -> List[Dict[str, Any]]:
    """Filter resources by type.

    Args:
        resources: List of normalized resource dictionaries
        resource_type: Terraform resource type (e.g., 'aws_s3_bucket')

    Returns:
        List of resources matching the specified type
    """
    return [r for r in resources if r["type"] == resource_type]


def get_nested_property(obj: Dict[str, Any], path: str) -> Any:
    """Get a nested property from an object using dot notation.

    Supports accessing nested dictionaries and list indices.
    Returns None if path doesn't exist.

    Args:
        obj: Dictionary to traverse
        path: Dot-notation path (e.g., 'versioning.enabled' or 'rules.0.status')

    Returns:
        Value at the specified path, or None if not found

    Examples:
        >>> obj = {"a": {"b": {"c": 123}}}
        >>> get_nested_property(obj, "a.b.c")
        123

        >>> obj = {"items": [{"name": "first"}, {"name": "second"}]}
        >>> get_nested_property(obj, "items.0.name")
        'first'
    """
    if not obj or not path:
        return None

    # Security: validate path before traversal
    from berm.security import validate_property_path

    try:
        validate_property_path(path)
    except (ValueError, SecurityError):
        # Invalid property path - return None instead of raising
        # This allows graceful handling of malformed rules
        return None

    parts = path.split(".")
    current = obj

    for part in parts:
        if current is None:
            return None

        # Handle list index access (e.g., "0", "1", "2")
        if isinstance(current, list):
            try:
                index = int(part)
                # Security: prevent array index DoS with excessively large indices
                if index < 0 or index >= MAX_ARRAY_INDEX:
                    return None
                if index < len(current):
                    current = current[index]
                else:
                    return None
            except (ValueError, IndexError):
                return None

        # Handle dictionary key access
        elif isinstance(current, dict):
            current = current.get(part)

        else:
            return None

    return current


def extract_resource_references(plan_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """Extract resource references from Terraform plan configuration.

    Parses the plan's configuration section to build a map of which resources
    reference which other resources. This is used for cross-resource validation
    to determine relationships between resources.

    Args:
        plan_data: Full Terraform plan JSON data (from terraform show -json)

    Returns:
        Dictionary mapping target resource addresses to list of dependent addresses:
        {
            "aws_s3_bucket.example": ["aws_s3_bucket_versioning.example_versioning"],
            "aws_lb.main": ["aws_lb_listener.https"]
        }

    Examples:
        If aws_s3_bucket_versioning.example has:
            bucket = aws_s3_bucket.main.id

        Then the result includes:
            {"aws_s3_bucket.main": ["aws_s3_bucket_versioning.example"]}
    """
    reference_map: Dict[str, List[str]] = {}

    # Navigate to configuration section
    config = plan_data.get("configuration", {})
    if not isinstance(config, dict):
        return reference_map

    root_module = config.get("root_module", {})
    if not isinstance(root_module, dict):
        return reference_map

    config_resources = root_module.get("resources", [])
    if not isinstance(config_resources, list):
        return reference_map

    # Process each resource configuration
    for resource in config_resources:
        if not isinstance(resource, dict):
            continue

        dependent_address = resource.get("address")
        if not dependent_address:
            continue

        expressions = resource.get("expressions", {})
        if not isinstance(expressions, dict):
            continue

        # Extract references from all expression properties
        _extract_references_from_expressions(
            expressions, dependent_address, reference_map
        )

    return reference_map


def _extract_references_from_expressions(
    expressions: Dict[str, Any],
    dependent_address: str,
    reference_map: Dict[str, List[str]],
) -> None:
    """Recursively extract references from expression objects.

    Terraform expressions can contain 'references' arrays that list the resources
    they depend on. This function traverses the expression tree to find all such
    references.

    Args:
        expressions: Dictionary of expression objects from Terraform configuration
        dependent_address: Address of the resource that contains these expressions
        reference_map: Dictionary to populate with discovered references (modified in-place)
    """
    if not isinstance(expressions, dict):
        return

    for key, value in expressions.items():
        if isinstance(value, dict):
            # Check if this expression has a references array
            if "references" in value and isinstance(value["references"], list):
                for ref in value["references"]:
                    if isinstance(ref, str):
                        # Extract the target address from the reference
                        # References can be like "aws_s3_bucket.example.id" or "aws_s3_bucket.example"
                        target_address = _extract_address_from_reference(ref)
                        if target_address:
                            if target_address not in reference_map:
                                reference_map[target_address] = []
                            if dependent_address not in reference_map[target_address]:
                                reference_map[target_address].append(dependent_address)

            # Recursively process nested expressions
            _extract_references_from_expressions(value, dependent_address, reference_map)

        elif isinstance(value, list):
            # Handle lists of expressions (e.g., for block resources)
            for item in value:
                if isinstance(item, dict):
                    _extract_references_from_expressions(
                        item, dependent_address, reference_map
                    )


def _extract_address_from_reference(reference: str) -> str:
    """Extract resource address from a Terraform reference string.

    Terraform references can include attribute access (e.g., .id, .arn).
    This function strips the attribute portion to get the base resource address.

    Args:
        reference: Terraform reference string (e.g., "aws_s3_bucket.example.id")

    Returns:
        Resource address (e.g., "aws_s3_bucket.example")

    Examples:
        >>> _extract_address_from_reference("aws_s3_bucket.example.id")
        "aws_s3_bucket.example"

        >>> _extract_address_from_reference("aws_s3_bucket.example")
        "aws_s3_bucket.example"

        >>> _extract_address_from_reference("module.vpc.aws_subnet.private")
        "module.vpc.aws_subnet.private"
    """
    if not reference:
        return ""

    # Split on dots
    parts = reference.split(".")

    # Need at least resource_type.resource_name (2 parts)
    if len(parts) < 2:
        return ""

    # Common pattern: resource_type.resource_name.attribute
    # We want to keep resource_type.resource_name
    # But also handle module.name.resource_type.resource_name

    # If starts with "module.", keep module.name.resource_type.resource_name
    if parts[0] == "module":
        # module.vpc.aws_subnet.private -> keep module.vpc.aws_subnet.private
        # module.vpc.aws_subnet.private.id -> keep module.vpc.aws_subnet.private
        if len(parts) >= 4:
            return ".".join(parts[:4])
        return reference

    # Otherwise, assume format: resource_type.resource_name[.attribute]
    # Keep only resource_type.resource_name
    return ".".join(parts[:2])


def extract_constant_values(plan_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract constant values from Terraform plan configuration.

    Retrieves static/constant values from resource expressions, which are useful
    for matching resources that use hardcoded values instead of dynamic references.

    Args:
        plan_data: Full Terraform plan JSON data (from terraform show -json)

    Returns:
        Dictionary mapping resource addresses to their constant values:
        {
            "aws_s3_bucket.example": {"bucket": "my-bucket-123"},
            "aws_s3_bucket_versioning.example": {"bucket": "my-bucket-123"}
        }
    """
    constant_map: Dict[str, Dict[str, Any]] = {}

    # Navigate to configuration section
    config = plan_data.get("configuration", {})
    if not isinstance(config, dict):
        return constant_map

    root_module = config.get("root_module", {})
    if not isinstance(root_module, dict):
        return constant_map

    config_resources = root_module.get("resources", [])
    if not isinstance(config_resources, list):
        return constant_map

    # Process each resource configuration
    for resource in config_resources:
        if not isinstance(resource, dict):
            continue

        address = resource.get("address")
        if not address:
            continue

        expressions = resource.get("expressions", {})
        if not isinstance(expressions, dict):
            continue

        # Extract constant values from expressions
        constants = {}
        for key, value in expressions.items():
            if isinstance(value, dict) and "constant_value" in value:
                constants[key] = value["constant_value"]

        if constants:
            constant_map[address] = constants

    return constant_map
