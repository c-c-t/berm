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


def load_terraform_plan(
    plan_path: str,
    _allow_absolute: bool = False,
    include_deletions: bool = False,
) -> List[Dict[str, Any]]:
    """Load and parse a Terraform plan JSON file.

    Extracts resource changes from the plan and normalizes them for evaluation.
    By default only includes resources that are being created, updated, or replaced.
    Excludes resources that are unchanged (no-op). Pure deletions are excluded unless
    include_deletions=True. Replacements (delete+create or create+delete) are always
    included regardless of include_deletions.

    Args:
        plan_path: Path to Terraform plan JSON file (output of 'terraform show -json')
        _allow_absolute: Internal parameter for testing - allows absolute paths
        include_deletions: When True, also include pure deletion actions

    Returns:
        List of resource dictionaries with normalized structure:
        [
            {
                "address": "aws_s3_bucket.example",
                "type": "aws_s3_bucket",
                "name": "example",
                "values": {...},  # Resource configuration
                "actions": ["create"] | ["update"] | ["delete", "create"] | ["create", "delete"] | ["delete"]
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

            # Always skip no-op
            if not actions or actions == ["no-op"]:
                continue

            # Replacements (delete+create or create+delete) are always included
            is_replacement = set(actions) == {"delete", "create"}

            # Skip pure deletions unless include_deletions is set
            if actions == ["delete"] and not include_deletions and not is_replacement:
                continue

            # Extract resource details
            address = change.get("address", "")
            resource_type = change.get("type", "")
            name = change.get("name", "")

            # Get the 'after' values (planned configuration)
            # For creates/updates, 'after' contains the new values
            # For deletions, fall back to 'before'
            values = change.get("change", {}).get("after", {})

            if values is None:
                values = change.get("change", {}).get("before", {})

            if values is None:
                values = {}

            resource = {
                "address": address,
                "type": resource_type,
                "name": name,
                "values": values,
                "actions": actions,
            }

            resources.append(resource)

        except Exception:
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
        return None

    parts = path.split(".")
    current = obj

    for part in parts:
        if current is None:
            return None

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

    Traverses both root-level resources and all child modules recursively so that
    module-scoped resources (e.g. module.s3_bucket.aws_s3_bucket.this) are correctly
    linked to their companion resources.

    Args:
        plan_data: Full Terraform plan JSON data (from terraform show -json)

    Returns:
        Dictionary mapping target resource addresses to list of dependent addresses:
        {
            "aws_s3_bucket.example": ["aws_s3_bucket_versioning.example_versioning"],
            "module.s3_bucket.aws_s3_bucket.this": ["module.s3_bucket.aws_s3_bucket_versioning.this"]
        }
    """
    reference_map: Dict[str, List[str]] = {}

    config = plan_data.get("configuration", {})
    if not isinstance(config, dict):
        return reference_map

    root_module = config.get("root_module", {})
    if not isinstance(root_module, dict):
        return reference_map

    _process_module_references(root_module, reference_map)

    return reference_map


def _process_module_references(
    module_config: Dict[str, Any],
    reference_map: Dict[str, List[str]],
    module_prefix: str = "",
) -> None:
    """Recursively process a module configuration block to extract resource references.

    Handles two Terraform plan JSON formats:
    - child_modules (list): resources carry fully-qualified addresses already.
      Used in planned_values and by some Terraform versions in configuration.
    - module_calls (dict): resources carry relative addresses that must be
      qualified with the module path prefix. Used in configuration by real
      terraform show -json output.

    Args:
        module_config: A module configuration block (root_module or nested module)
        reference_map: Dictionary to populate with discovered references (modified in-place)
        module_prefix: Fully-qualified prefix for the current module scope, e.g.
            "module.s3_bucket". Empty string for root or already-qualified scopes.
    """
    for resource in module_config.get("resources", []):
        if not isinstance(resource, dict):
            continue

        raw_address = resource.get("address")
        if not raw_address:
            continue

        dependent_address = _qualify_module_address(raw_address, module_prefix)

        expressions = resource.get("expressions", {})
        if not isinstance(expressions, dict):
            continue

        _extract_references_from_expressions(
            expressions, dependent_address, reference_map, module_prefix
        )

    # child_modules format: addresses are already fully qualified, no prefix needed
    for child_module in module_config.get("child_modules", []):
        if isinstance(child_module, dict):
            _process_module_references(child_module, reference_map, module_prefix="")

    # module_calls format: addresses are relative, must be qualified with the module path
    module_calls = module_config.get("module_calls", {})
    if isinstance(module_calls, dict):
        for call_name, call_config in module_calls.items():
            if not isinstance(call_config, dict):
                continue
            child_module = call_config.get("module", {})
            if not isinstance(child_module, dict):
                continue
            child_prefix = (
                f"{module_prefix}.{call_name}" if module_prefix else f"module.{call_name}"
            )
            _process_module_references(child_module, reference_map, child_prefix)


_NON_RESOURCE_PREFIXES = (
    "var.", "local.", "data.", "path.", "self.", "each.", "count.", "module.",
)


def _qualify_module_address(address: str, module_prefix: str) -> str:
    """Qualify a relative resource address with a module prefix.

    In the module_calls format, resource addresses inside a module are relative
    (e.g. "aws_s3_bucket.this"). This prepends the module path to produce the
    fully-qualified address that matches resource_changes
    (e.g. "module.s3_bucket.aws_s3_bucket.this").

    Addresses that are already absolute (start with "module.") or are not
    resource references (var.*, local.*, data.*, etc.) are returned unchanged,
    so this is safe to call unconditionally.

    Args:
        address: Possibly-relative address (e.g. "aws_s3_bucket.this")
        module_prefix: Fully-qualified module prefix (e.g. "module.s3_bucket"),
            or empty string when no qualification is needed.

    Returns:
        Fully-qualified address (e.g. "module.s3_bucket.aws_s3_bucket.this")
    """
    if not module_prefix or not address:
        return address
    if any(address.startswith(p) for p in _NON_RESOURCE_PREFIXES):
        return address
    return f"{module_prefix}.{address}"


def _extract_references_from_expressions(
    expressions: Dict[str, Any],
    dependent_address: str,
    reference_map: Dict[str, List[str]],
    module_prefix: str = "",
) -> None:
    """Recursively extract references from a Terraform expression tree.

    Args:
        expressions: Dictionary of expression objects from Terraform configuration
        dependent_address: Address of the resource that owns these expressions
        reference_map: Dictionary to populate with discovered references (modified in-place)
        module_prefix: Module prefix used to qualify relative reference addresses
            (empty when addresses are already fully qualified)
    """
    if not isinstance(expressions, dict):
        return

    for value in expressions.values():
        if isinstance(value, dict):
            if "references" in value and isinstance(value["references"], list):
                for ref in value["references"]:
                    if isinstance(ref, str):
                        target_address = _extract_address_from_reference(ref)
                        if target_address:
                            target_address = _qualify_module_address(
                                target_address, module_prefix
                            )
                            if target_address not in reference_map:
                                reference_map[target_address] = []
                            if dependent_address not in reference_map[target_address]:
                                reference_map[target_address].append(dependent_address)

            _extract_references_from_expressions(
                value, dependent_address, reference_map, module_prefix
            )

        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _extract_references_from_expressions(
                        item, dependent_address, reference_map, module_prefix
                    )


def _extract_address_from_reference(reference: str) -> str:
    """Extract resource address from a Terraform reference string.

    Strips trailing attribute access (e.g. .id, .arn) to return the base
    resource address. Handles arbitrary module nesting depth.

    Args:
        reference: Terraform reference string (e.g., "aws_s3_bucket.example.id")

    Returns:
        Resource address (e.g., "aws_s3_bucket.example")

    Examples:
        >>> _extract_address_from_reference("aws_s3_bucket.example.id")
        "aws_s3_bucket.example"

        >>> _extract_address_from_reference("module.vpc.aws_subnet.private.id")
        "module.vpc.aws_subnet.private"

        >>> _extract_address_from_reference("module.network.module.subnets.aws_subnet.private.id")
        "module.network.module.subnets.aws_subnet.private"
    """
    if not reference:
        return ""

    parts = reference.split(".")

    if len(parts) < 2:
        return ""

    if parts[0] != "module":
        # Root resource: resource_type.resource_name[.attribute...]
        return ".".join(parts[:2])

    # Module resource: consume all leading "module.<name>" pairs, then take
    # the following "resource_type.resource_name" pair.
    i = 0
    while i < len(parts) - 1 and parts[i] == "module":
        i += 2  # skip "module" and the module name

    # parts[i:i+2] is resource_type.resource_name (if present)
    if i + 1 < len(parts):
        return ".".join(parts[: i + 2])

    return ".".join(parts[:i])


def extract_constant_values(plan_data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Extract constant values from Terraform plan configuration.

    Retrieves static/constant values from resource expressions, which are useful
    for matching resources that use hardcoded values instead of dynamic references.
    Traverses child modules recursively so module-scoped resources are included.

    Args:
        plan_data: Full Terraform plan JSON data (from terraform show -json)

    Returns:
        Dictionary mapping resource addresses to their constant values:
        {
            "aws_s3_bucket.example": {"bucket": "my-bucket-123"},
            "module.s3_bucket.aws_s3_bucket.this": {"force_destroy": False}
        }
    """
    constant_map: Dict[str, Dict[str, Any]] = {}

    config = plan_data.get("configuration", {})
    if not isinstance(config, dict):
        return constant_map

    root_module = config.get("root_module", {})
    if not isinstance(root_module, dict):
        return constant_map

    _process_module_constants(root_module, constant_map)

    return constant_map


def _process_module_constants(
    module_config: Dict[str, Any],
    constant_map: Dict[str, Dict[str, Any]],
    module_prefix: str = "",
) -> None:
    """Recursively process a module configuration block to extract constant values.

    Handles both child_modules (fully-qualified addresses) and module_calls
    (relative addresses) formats. See _process_module_references for details.

    Args:
        module_config: A module configuration block (root_module or nested module)
        constant_map: Dictionary to populate with discovered constant values (modified in-place)
        module_prefix: Fully-qualified prefix for the current module scope.
    """
    for resource in module_config.get("resources", []):
        if not isinstance(resource, dict):
            continue

        raw_address = resource.get("address")
        if not raw_address:
            continue

        address = _qualify_module_address(raw_address, module_prefix)

        expressions = resource.get("expressions", {})
        if not isinstance(expressions, dict):
            continue

        constants = {
            key: value["constant_value"]
            for key, value in expressions.items()
            if isinstance(value, dict) and "constant_value" in value
        }

        if constants:
            constant_map[address] = constants

    # child_modules format: addresses already fully qualified
    for child_module in module_config.get("child_modules", []):
        if isinstance(child_module, dict):
            _process_module_constants(child_module, constant_map, module_prefix="")

    # module_calls format: addresses are relative, must be qualified
    module_calls = module_config.get("module_calls", {})
    if isinstance(module_calls, dict):
        for call_name, call_config in module_calls.items():
            if not isinstance(call_config, dict):
                continue
            child_module = call_config.get("module", {})
            if not isinstance(child_module, dict):
                continue
            child_prefix = (
                f"{module_prefix}.{call_name}" if module_prefix else f"module.{call_name}"
            )
            _process_module_constants(child_module, constant_map, child_prefix)
