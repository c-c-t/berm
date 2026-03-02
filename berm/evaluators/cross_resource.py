"""Cross-resource relationship evaluator.

This evaluator validates that when certain resources exist in a Terraform plan,
required companion resources also exist and meet specified conditions.

Example use cases:
- S3 buckets must have versioning and encryption resources
- Load balancers must have HTTPS listeners
- RDS instances must have backup and security group configurations
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from berm.loaders.terraform import (
    extract_constant_values,
    extract_resource_references,
    get_nested_property,
)
from berm.models.rule import RequiredResource, Rule
from berm.models.violation import Violation


class CrossResourceEvaluator:
    """Evaluates cross-resource relationships in Terraform plans.

    This evaluator checks that when a primary resource exists, all required
    related resources also exist and optionally meet specified conditions.

    Supports three relationship matching strategies:
    1. Reference-based: Uses Terraform's reference graph from plan configuration
    2. Constant value matching: Matches resources by comparing static property values
    3. Name-based: Matches resources with the same name suffix

    Example:
        evaluator = CrossResourceEvaluator()
        violations = evaluator.evaluate(rule, resources, plan_data)
    """

    def evaluate(
        self,
        rule: Rule,
        resources: List[Dict[str, Any]],
        plan_data: Optional[Dict[str, Any]] = None,
    ) -> List[Violation]:
        """Evaluate a cross-resource rule against resources.

        Args:
            rule: The policy rule to evaluate (must have requires_resources)
            resources: List of normalized resource dictionaries from Terraform plan
            plan_data: Full Terraform plan data (optional, for reference extraction)

        Returns:
            List of violations found (empty if all resources comply)
        """
        # Skip if not a cross-resource rule
        if not rule.requires_resources or len(rule.requires_resources) == 0:
            return []

        violations = []

        # Build resource index for fast lookups
        resource_index = self._build_resource_index(resources)

        # Extract references and constant values from plan configuration
        reference_map: Dict[str, List[str]] = {}
        constant_map: Dict[str, Dict[str, Any]] = {}

        if plan_data:
            reference_map = extract_resource_references(plan_data)
            constant_map = extract_constant_values(plan_data)

        # Get primary resources matching the rule's resource_type
        primary_resources = self._get_primary_resources(rule, resource_index)

        # Check each primary resource
        for primary in primary_resources:
            # Validate each required resource relationship
            for required in rule.requires_resources:
                violations.extend(
                    self._check_required_resource(
                        rule,
                        primary,
                        required,
                        resource_index,
                        reference_map,
                        constant_map,
                    )
                )

        return violations

    def _build_resource_index(
        self, resources: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build index structures for fast resource lookups.

        Args:
            resources: List of normalized resource dictionaries

        Returns:
            Dictionary containing:
            - by_type: Resources indexed by type
            - by_address: Resources indexed by address
        """
        index = {
            "by_type": defaultdict(list),
            "by_address": {},
        }

        for resource in resources:
            resource_type = resource.get("type", "")
            resource_address = resource.get("address", "")

            if resource_type:
                index["by_type"][resource_type].append(resource)

            if resource_address:
                index["by_address"][resource_address] = resource

        return index

    def _get_primary_resources(
        self, rule: Rule, resource_index: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Get all primary resources matching the rule's resource type.

        Args:
            rule: The policy rule
            resource_index: Resource index from _build_resource_index

        Returns:
            List of primary resources
        """
        if rule.resource_type:
            return resource_index["by_type"].get(rule.resource_type, [])
        elif rule.resource_types:
            primary_resources = []
            for resource_type in rule.resource_types:
                primary_resources.extend(
                    resource_index["by_type"].get(resource_type, [])
                )
            return primary_resources
        return []

    def _check_required_resource(
        self,
        rule: Rule,
        primary: Dict[str, Any],
        required: RequiredResource,
        resource_index: Dict[str, Any],
        reference_map: Dict[str, List[str]],
        constant_map: Dict[str, Dict[str, Any]],
    ) -> List[Violation]:
        """Check if required resource exists and meets conditions.

        Args:
            rule: The policy rule
            primary: Primary resource dictionary
            required: Required resource specification
            resource_index: Resource index
            reference_map: Map of resource references
            constant_map: Map of constant values

        Returns:
            List of violations (empty if compliant)
        """
        # Check if rule should only apply to creation actions
        if rule.only_on_create:
            actions = primary.get("actions", [])
            if not rule.is_creation_action(actions):
                # Skip this resource - rule only applies to creations
                return []

        # Find related resources using appropriate strategy
        related_resources = self._find_related_resources(
            primary, required, resource_index, reference_map, constant_map
        )

        violations = []

        # Check minimum count requirement
        if len(related_resources) < required.min_count:
            violations.append(
                self._create_violation(
                    rule,
                    primary,
                    required,
                    f"Missing required {required.resource_type} "
                    f"(found {len(related_resources)}, need {required.min_count})",
                )
            )
            return violations  # No point checking conditions if resource missing

        # Check maximum count requirement
        if required.max_count is not None and len(related_resources) > required.max_count:
            violations.append(
                self._create_violation(
                    rule,
                    primary,
                    required,
                    f"Too many {required.resource_type} "
                    f"(found {len(related_resources)}, max {required.max_count})",
                )
            )

        # Validate conditions on related resources
        if required.conditions:
            for related_resource in related_resources:
                condition_violations = self._validate_conditions(
                    rule, primary, required, related_resource
                )
                violations.extend(condition_violations)

        return violations

    def _find_related_resources(
        self,
        primary: Dict[str, Any],
        required: RequiredResource,
        resource_index: Dict[str, Any],
        reference_map: Dict[str, List[str]],
        constant_map: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Find resources related to the primary resource.

        Uses multiple strategies in order:
        1. Reference-based matching (from Terraform plan configuration)
        2. Constant value matching (for hardcoded values)
        3. Name-based matching (fallback)

        Args:
            primary: Primary resource dictionary
            required: Required resource specification
            resource_index: Resource index
            reference_map: Map of resource references
            constant_map: Map of constant values

        Returns:
            List of related resources
        """
        if required.relationship == "referenced_by_primary":
            return self._find_by_referenced_by_primary(
                primary, required, resource_index, reference_map, constant_map
            )
        elif required.relationship == "references_primary":
            return self._find_by_references_primary(
                primary, required, resource_index, reference_map, constant_map
            )
        elif required.relationship == "same_name_suffix":
            return self._find_by_name_suffix(primary, required, resource_index)

        return []

    def _find_by_referenced_by_primary(
        self,
        primary: Dict[str, Any],
        required: RequiredResource,
        resource_index: Dict[str, Any],
        reference_map: Dict[str, List[str]],
        constant_map: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Find resources that reference the primary resource.

        Example: Find aws_s3_bucket_versioning resources where bucket = aws_s3_bucket.example.id

        Args:
            primary: Primary resource dictionary
            required: Required resource specification
            resource_index: Resource index
            reference_map: Map of resource references
            constant_map: Map of constant values

        Returns:
            List of matching resources
        """
        primary_address = primary.get("address", "")
        matches = []

        # Strategy 1: Use reference map (dynamic references)
        if primary_address in reference_map:
            dependent_addresses = reference_map[primary_address]
            for dep_address in dependent_addresses:
                dep_resource = resource_index["by_address"].get(dep_address)
                if dep_resource and dep_resource.get("type") == required.resource_type:
                    matches.append(dep_resource)

        # Strategy 2: Match by constant values (static hardcoded values)
        if required.reference_property:
            # Get the primary's identifier value
            primary_identifier = self._get_resource_identifier(primary)

            # Check all resources of the required type
            for candidate in resource_index["by_type"].get(required.resource_type, []):
                candidate_address = candidate.get("address", "")

                # Check if candidate has a constant value that matches primary's identifier
                if candidate_address in constant_map:
                    constants = constant_map[candidate_address]
                    ref_value = constants.get(required.reference_property)

                    if ref_value and self._matches_identifier(
                        ref_value, primary_identifier, primary_address
                    ):
                        if candidate not in matches:
                            matches.append(candidate)

        return matches

    def _find_by_references_primary(
        self,
        primary: Dict[str, Any],
        required: RequiredResource,
        resource_index: Dict[str, Any],
        reference_map: Dict[str, List[str]],
        constant_map: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Find resources that the primary resource references.

        Example: Find aws_lb resources that aws_lb_listener.load_balancer_arn references

        Args:
            primary: Primary resource dictionary
            required: Required resource specification
            resource_index: Resource index
            reference_map: Map of resource references
            constant_map: Map of constant values

        Returns:
            List of matching resources
        """
        primary_address = primary.get("address", "")
        matches = []

        # Check all resources of the required type to see if primary references them
        for candidate in resource_index["by_type"].get(required.resource_type, []):
            candidate_address = candidate.get("address", "")

            # Strategy 1: Check if primary is in the candidate's dependents list
            if candidate_address in reference_map:
                if primary_address in reference_map[candidate_address]:
                    matches.append(candidate)

        return matches

    def _find_by_name_suffix(
        self,
        primary: Dict[str, Any],
        required: RequiredResource,
        resource_index: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Find resources with matching name suffix.

        Example: aws_s3_bucket.example matches aws_s3_bucket_versioning.example

        Args:
            primary: Primary resource dictionary
            required: Required resource specification
            resource_index: Resource index

        Returns:
            List of matching resources
        """
        primary_name = primary.get("name", "")
        matches = []

        if not primary_name:
            return matches

        for candidate in resource_index["by_type"].get(required.resource_type, []):
            if candidate.get("name") == primary_name:
                matches.append(candidate)

        return matches

    def _get_resource_identifier(self, resource: Dict[str, Any]) -> str:
        """Extract identifier from resource values.

        Looks for common identifier properties in resource values.

        Args:
            resource: Resource dictionary

        Returns:
            Resource identifier (e.g., bucket name, ID, ARN)
        """
        values = resource.get("values", {})

        # Common identifier properties (in priority order)
        identifier_props = [
            "bucket",  # S3 buckets
            "id",
            "name",
            "identifier",
            "arn",
        ]

        for prop in identifier_props:
            value = values.get(prop)
            if value and isinstance(value, str):
                return value

        # Fallback to resource address
        return resource.get("address", "")

    def _matches_identifier(
        self, ref_value: Any, primary_id: str, primary_address: str
    ) -> bool:
        """Check if reference value matches primary resource identifier.

        Args:
            ref_value: Reference value from dependent resource
            primary_id: Primary resource's identifier
            primary_address: Primary resource's address

        Returns:
            True if reference matches primary
        """
        if not isinstance(ref_value, str):
            return False

        return (
            ref_value == primary_id
            or ref_value == primary_address
            or primary_address in ref_value
        )

    def _validate_conditions(
        self,
        rule: Rule,
        primary: Dict[str, Any],
        required: RequiredResource,
        related_resource: Dict[str, Any],
    ) -> List[Violation]:
        """Validate that related resource meets all specified conditions.

        Args:
            rule: The policy rule
            primary: Primary resource dictionary
            required: Required resource specification
            related_resource: Related resource to validate

        Returns:
            List of violations (empty if all conditions met)
        """
        if not required.conditions:
            return []

        violations = []
        related_values = related_resource.get("values", {})
        related_address = related_resource.get("address", "unknown")

        for property_path, expected_value in required.conditions.items():
            actual_value = get_nested_property(related_values, property_path)

            # Check if value matches expectation
            if actual_value != expected_value:
                message = (
                    f"Related resource {related_address} fails condition: "
                    f"{property_path} is {repr(actual_value)}, expected {repr(expected_value)}"
                )
                violations.append(
                    self._create_violation(rule, primary, required, message)
                )

        return violations

    def _create_violation(
        self,
        rule: Rule,
        primary: Dict[str, Any],
        required: RequiredResource,
        detail_message: str,
    ) -> Violation:
        """Create a violation for cross-resource rule failure.

        Args:
            rule: The policy rule
            primary: Primary resource dictionary
            required: Required resource specification
            detail_message: Detailed message about the failure

        Returns:
            Violation object
        """
        primary_address = primary.get("address", "unknown")
        primary_type = primary.get("type", "unknown")

        # Format the base message with resource name
        base_message = rule.format_message(primary_address)

        # Append detail message
        if required.message_suffix:
            full_message = f"{base_message}: {detail_message} {required.message_suffix}"
        else:
            full_message = f"{base_message}: {detail_message}"

        return Violation(
            rule_id=rule.id,
            rule_name=rule.name,
            resource_name=primary_address,
            resource_type=primary_type,
            severity=rule.severity,
            message=full_message,
        )
