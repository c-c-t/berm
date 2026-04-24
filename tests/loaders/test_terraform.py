"""Tests for Terraform plan loader."""

import json
from pathlib import Path

import pytest

from berm.loaders.terraform import (
    TerraformPlanLoadError,
    _extract_address_from_reference,
    extract_constant_values,
    extract_resource_references,
    get_nested_property,
    get_resource_by_type,
    load_terraform_plan,
)


def test_load_terraform_plan(sample_plan_file):
    """Test loading a Terraform plan file."""
    resources = load_terraform_plan(str(sample_plan_file), _allow_absolute=True)

    # Should load resources (excluding deleted ones)
    assert len(resources) > 0
    assert all(isinstance(r, dict) for r in resources)

    # Each resource should have expected keys
    for resource in resources:
        assert "address" in resource
        assert "type" in resource
        assert "name" in resource
        assert "values" in resource


def test_load_terraform_plan_nonexistent():
    """Test loading non-existent file."""
    with pytest.raises(TerraformPlanLoadError, match="does not exist"):
        load_terraform_plan("/nonexistent/plan.json", _allow_absolute=True)


def test_load_terraform_plan_not_a_file(tmp_path):
    """Test loading when path is a directory."""
    # Create a .json file that is actually a directory
    fake_file = tmp_path / "fake.json"
    fake_file.mkdir()
    with pytest.raises(TerraformPlanLoadError, match="not a file"):
        load_terraform_plan(str(fake_file), _allow_absolute=True)


def test_load_terraform_plan_invalid_json(tmp_path):
    """Test loading invalid JSON."""
    plan_file = tmp_path / "invalid.json"
    plan_file.write_text("{ invalid json }")

    with pytest.raises(TerraformPlanLoadError, match="Invalid JSON"):
        load_terraform_plan(str(plan_file), _allow_absolute=True)


def test_load_terraform_plan_not_object(tmp_path):
    """Test loading plan that's not a JSON object."""
    plan_file = tmp_path / "array.json"
    plan_file.write_text('["not", "an", "object"]')

    with pytest.raises(TerraformPlanLoadError, match="must contain a JSON object"):
        load_terraform_plan(str(plan_file), _allow_absolute=True)


def test_load_terraform_plan_excludes_deleted(tmp_path):
    """Test that deleted resources are excluded."""
    plan_data = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.kept",
                "type": "aws_s3_bucket",
                "name": "kept",
                "change": {
                    "actions": ["create"],
                    "after": {"bucket": "my-bucket"},
                },
            },
            {
                "address": "aws_s3_bucket.deleted",
                "type": "aws_s3_bucket",
                "name": "deleted",
                "change": {
                    "actions": ["delete"],
                    "before": {"bucket": "old-bucket"},
                    "after": None,
                },
            },
        ]
    }

    plan_file = tmp_path / "plan.json"
    with open(plan_file, "w") as f:
        json.dump(plan_data, f)

    resources = load_terraform_plan(str(plan_file), _allow_absolute=True)

    # Should only include the created resource, not the deleted one
    assert len(resources) == 1
    assert resources[0]["address"] == "aws_s3_bucket.kept"


def test_load_terraform_plan_includes_deletions_when_requested(tmp_path):
    """Test that deleted resources are included when include_deletions=True."""
    plan_data = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.kept",
                "type": "aws_s3_bucket",
                "name": "kept",
                "change": {
                    "actions": ["create"],
                    "after": {"bucket": "my-bucket"},
                },
            },
            {
                "address": "aws_db_instance.deleted",
                "type": "aws_db_instance",
                "name": "deleted",
                "change": {
                    "actions": ["delete"],
                    "before": {"identifier": "old-db"},
                    "after": None,
                },
            },
        ]
    }

    plan_file = tmp_path / "plan.json"
    with open(plan_file, "w") as f:
        json.dump(plan_data, f)

    resources = load_terraform_plan(str(plan_file), _allow_absolute=True, include_deletions=True)

    # Should include both the created and deleted resources
    assert len(resources) == 2
    addresses = {r["address"] for r in resources}
    assert "aws_s3_bucket.kept" in addresses
    assert "aws_db_instance.deleted" in addresses

    # Verify the deleted resource has the correct action
    deleted = next(r for r in resources if r["address"] == "aws_db_instance.deleted")
    assert deleted["actions"] == ["delete"]


def test_load_terraform_plan_includes_replacements_always(tmp_path):
    """Test that replaced resources are always included regardless of include_deletions flag."""
    plan_data = {
        "resource_changes": [
            {
                "address": "aws_db_instance.replaced",
                "type": "aws_db_instance",
                "name": "replaced",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"identifier": "old-db"},
                    "after": {"identifier": "new-db"},
                },
            },
        ]
    }

    plan_file = tmp_path / "plan.json"
    with open(plan_file, "w") as f:
        json.dump(plan_data, f)

    # Test without include_deletions
    resources_no_flag = load_terraform_plan(str(plan_file), _allow_absolute=True, include_deletions=False)
    assert len(resources_no_flag) == 1
    assert resources_no_flag[0]["actions"] == ["delete", "create"]

    # Test with include_deletions (should still be included)
    resources_with_flag = load_terraform_plan(str(plan_file), _allow_absolute=True, include_deletions=True)
    assert len(resources_with_flag) == 1
    assert resources_with_flag[0]["actions"] == ["delete", "create"]


def test_load_terraform_plan_excludes_noop(tmp_path):
    """Test that no-op resources are excluded."""
    plan_data = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.changed",
                "type": "aws_s3_bucket",
                "name": "changed",
                "change": {
                    "actions": ["update"],
                    "after": {"bucket": "my-bucket"},
                },
            },
            {
                "address": "aws_s3_bucket.unchanged",
                "type": "aws_s3_bucket",
                "name": "unchanged",
                "change": {
                    "actions": ["no-op"],
                    "after": {"bucket": "same-bucket"},
                },
            },
        ]
    }

    plan_file = tmp_path / "plan.json"
    with open(plan_file, "w") as f:
        json.dump(plan_data, f)

    resources = load_terraform_plan(str(plan_file), _allow_absolute=True)

    # Should only include the changed resource
    assert len(resources) == 1
    assert resources[0]["address"] == "aws_s3_bucket.changed"


def test_load_terraform_plan_includes_replaced(tmp_path):
    """Test that replaced resources are INCLUDED for validation."""
    plan_data = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.kept",
                "type": "aws_s3_bucket",
                "name": "kept",
                "change": {
                    "actions": ["create"],
                    "after": {"bucket": "new-bucket"},
                },
            },
            {
                "address": "aws_s3_bucket.replaced_standard",
                "type": "aws_s3_bucket",
                "name": "replaced_standard",
                "change": {
                    "actions": ["delete", "create"],  # Standard replace
                    "before": {"bucket": "old-bucket"},
                    "after": {"bucket": "replacement-bucket"},
                },
            },
            {
                "address": "aws_s3_bucket.replaced_create_before_destroy",
                "type": "aws_s3_bucket",
                "name": "replaced_create_before_destroy",
                "change": {
                    "actions": ["create", "delete"],  # create_before_destroy
                    "before": {"bucket": "old-bucket-2"},
                    "after": {"bucket": "replacement-bucket-2"},
                },
            },
        ]
    }

    plan_file = tmp_path / "plan.json"
    with open(plan_file, "w") as f:
        json.dump(plan_data, f)

    resources = load_terraform_plan(str(plan_file), _allow_absolute=True)

    # Should include ALL THREE: the created resource AND both replaced ones
    assert len(resources) == 3
    addresses = [r["address"] for r in resources]
    assert "aws_s3_bucket.kept" in addresses
    assert "aws_s3_bucket.replaced_standard" in addresses
    assert "aws_s3_bucket.replaced_create_before_destroy" in addresses

    # Verify replaced resources use their "after" values
    replaced_standard = [r for r in resources if r["address"] == "aws_s3_bucket.replaced_standard"][0]
    assert replaced_standard["values"]["bucket"] == "replacement-bucket"


def test_load_terraform_plan_preserves_actions(tmp_path):
    """Test that actions are preserved in normalized resources."""
    plan_data = {
        "resource_changes": [
            {
                "address": "aws_s3_bucket.created",
                "type": "aws_s3_bucket",
                "name": "created",
                "change": {
                    "actions": ["create"],
                    "after": {"bucket": "new-bucket"},
                },
            },
            {
                "address": "aws_s3_bucket.updated",
                "type": "aws_s3_bucket",
                "name": "updated",
                "change": {
                    "actions": ["update"],
                    "after": {"bucket": "existing-bucket"},
                },
            },
            {
                "address": "aws_s3_bucket.replaced",
                "type": "aws_s3_bucket",
                "name": "replaced",
                "change": {
                    "actions": ["delete", "create"],
                    "after": {"bucket": "replacement-bucket"},
                },
            },
        ]
    }

    plan_file = tmp_path / "plan.json"
    with open(plan_file, "w") as f:
        json.dump(plan_data, f)

    resources = load_terraform_plan(str(plan_file), _allow_absolute=True)

    # Should have all three resources with actions preserved
    assert len(resources) == 3

    created = [r for r in resources if r["address"] == "aws_s3_bucket.created"][0]
    assert created["actions"] == ["create"]

    updated = [r for r in resources if r["address"] == "aws_s3_bucket.updated"][0]
    assert updated["actions"] == ["update"]

    replaced = [r for r in resources if r["address"] == "aws_s3_bucket.replaced"][0]
    assert replaced["actions"] == ["delete", "create"]


def test_get_resource_by_type(sample_resources):
    """Test filtering resources by type."""
    s3_resources = get_resource_by_type(sample_resources, "aws_s3_bucket")
    assert len(s3_resources) == 2
    assert all(r["type"] == "aws_s3_bucket" for r in s3_resources)

    db_resources = get_resource_by_type(sample_resources, "aws_db_instance")
    assert len(db_resources) == 1
    assert db_resources[0]["type"] == "aws_db_instance"

    # Non-existent type
    other_resources = get_resource_by_type(sample_resources, "aws_lambda_function")
    assert len(other_resources) == 0


def test_get_nested_property_simple():
    """Test getting simple nested properties."""
    obj = {"a": {"b": {"c": 123}}}

    assert get_nested_property(obj, "a") == {"b": {"c": 123}}
    assert get_nested_property(obj, "a.b") == {"c": 123}
    assert get_nested_property(obj, "a.b.c") == 123


def test_get_nested_property_missing():
    """Test getting non-existent properties."""
    obj = {"a": {"b": 123}}

    assert get_nested_property(obj, "x") is None
    assert get_nested_property(obj, "a.x") is None
    assert get_nested_property(obj, "a.b.c") is None


def test_get_nested_property_list_index():
    """Test accessing list elements by index."""
    obj = {"items": [{"name": "first"}, {"name": "second"}, {"name": "third"}]}

    assert get_nested_property(obj, "items.0") == {"name": "first"}
    assert get_nested_property(obj, "items.1") == {"name": "second"}
    assert get_nested_property(obj, "items.0.name") == "first"
    assert get_nested_property(obj, "items.2.name") == "third"


def test_get_nested_property_list_out_of_bounds():
    """Test accessing list with invalid index."""
    obj = {"items": [{"name": "only"}]}

    assert get_nested_property(obj, "items.1") is None
    assert get_nested_property(obj, "items.5") is None
    assert get_nested_property(obj, "items.-1") is None


def test_get_nested_property_empty_path():
    """Test with empty path."""
    obj = {"a": 123}

    assert get_nested_property(obj, "") is None


def test_get_nested_property_none_object():
    """Test with None object."""
    assert get_nested_property(None, "a.b.c") is None


def test_get_nested_property_complex():
    """Test complex nested structure."""
    obj = {
        "versioning_configuration": [
            {"status": "Enabled", "mfa_delete": "Disabled"}
        ],
        "tags": {"Environment": "prod", "Team": "platform"},
    }

    assert get_nested_property(obj, "versioning_configuration.0.status") == "Enabled"
    assert get_nested_property(obj, "tags.Environment") == "prod"
    assert get_nested_property(obj, "tags.Team") == "platform"


# Tests for cross-resource reference extraction


def test_extract_resource_references_basic():
    """Test extracting basic resource references from plan."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.example",
                        "type": "aws_s3_bucket",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket"}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_versioning.example",
                        "type": "aws_s3_bucket_versioning",
                        "expressions": {
                            "bucket": {
                                "references": ["aws_s3_bucket.example.id", "aws_s3_bucket.example"]
                            }
                        }
                    }
                ]
            }
        }
    }

    references = extract_resource_references(plan_data)

    # Should map aws_s3_bucket.example -> [aws_s3_bucket_versioning.example]
    assert "aws_s3_bucket.example" in references
    assert "aws_s3_bucket_versioning.example" in references["aws_s3_bucket.example"]


def test_extract_resource_references_multiple_dependents():
    """Test extracting references when multiple resources reference the same target."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.main",
                        "expressions": {}
                    },
                    {
                        "address": "aws_s3_bucket_versioning.main",
                        "expressions": {
                            "bucket": {"references": ["aws_s3_bucket.main.id"]}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_public_access_block.main",
                        "expressions": {
                            "bucket": {"references": ["aws_s3_bucket.main.id"]}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_server_side_encryption_configuration.main",
                        "expressions": {
                            "bucket": {"references": ["aws_s3_bucket.main"]}
                        }
                    }
                ]
            }
        }
    }

    references = extract_resource_references(plan_data)

    # All three resources should reference aws_s3_bucket.main
    assert "aws_s3_bucket.main" in references
    assert len(references["aws_s3_bucket.main"]) == 3
    assert "aws_s3_bucket_versioning.main" in references["aws_s3_bucket.main"]
    assert "aws_s3_bucket_public_access_block.main" in references["aws_s3_bucket.main"]
    assert "aws_s3_bucket_server_side_encryption_configuration.main" in references["aws_s3_bucket.main"]


def test_extract_resource_references_nested_expressions():
    """Test extracting references from nested expression structures."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_lb_listener.https",
                        "expressions": {
                            "load_balancer_arn": {
                                "references": ["aws_lb.main.arn"]
                            },
                            "default_action": [
                                {
                                    "target_group_arn": {
                                        "references": ["aws_lb_target_group.app.arn"]
                                    }
                                }
                            ]
                        }
                    }
                ]
            }
        }
    }

    references = extract_resource_references(plan_data)

    # Should extract both references
    assert "aws_lb.main" in references
    assert "aws_lb_listener.https" in references["aws_lb.main"]
    assert "aws_lb_target_group.app" in references
    assert "aws_lb_listener.https" in references["aws_lb_target_group.app"]


def test_extract_resource_references_missing_configuration():
    """Test extracting references when configuration section is missing."""
    plan_data = {
        "resource_changes": []
    }

    references = extract_resource_references(plan_data)

    # Should return empty dict without error
    assert references == {}


def test_extract_resource_references_empty_references():
    """Test handling resources with no references."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.standalone",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket"}
                        }
                    }
                ]
            }
        }
    }

    references = extract_resource_references(plan_data)

    # Standalone resource should not appear in reference map
    assert "aws_s3_bucket.standalone" not in references


def test_extract_address_from_reference():
    """Test extracting resource address from reference strings."""
    # Basic resource reference with attribute
    assert _extract_address_from_reference("aws_s3_bucket.example.id") == "aws_s3_bucket.example"

    # Resource reference without attribute
    assert _extract_address_from_reference("aws_s3_bucket.example") == "aws_s3_bucket.example"

    # Module resource reference
    assert _extract_address_from_reference("module.vpc.aws_subnet.private") == "module.vpc.aws_subnet.private"

    # Module resource reference with attribute
    assert _extract_address_from_reference("module.vpc.aws_subnet.private.id") == "module.vpc.aws_subnet.private"

    # Empty string
    assert _extract_address_from_reference("") == ""

    # Invalid (too short)
    assert _extract_address_from_reference("single") == ""


def test_extract_constant_values():
    """Test extracting constant values from plan configuration."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.example",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket-123"},
                            "force_destroy": {"constant_value": False}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_versioning.example",
                        "expressions": {
                            "bucket": {"constant_value": "my-bucket-123"}
                        }
                    },
                    {
                        "address": "aws_s3_bucket_public_access_block.other",
                        "expressions": {
                            "bucket": {"references": ["aws_s3_bucket.other.id"]}
                        }
                    }
                ]
            }
        }
    }

    constants = extract_constant_values(plan_data)

    # Should extract constant values from first two resources
    assert "aws_s3_bucket.example" in constants
    assert constants["aws_s3_bucket.example"]["bucket"] == "my-bucket-123"
    assert constants["aws_s3_bucket.example"]["force_destroy"] is False

    assert "aws_s3_bucket_versioning.example" in constants
    assert constants["aws_s3_bucket_versioning.example"]["bucket"] == "my-bucket-123"

    # Third resource has no constant values (uses reference)
    assert "aws_s3_bucket_public_access_block.other" not in constants


def test_extract_constant_values_missing_configuration():
    """Test extracting constant values when configuration is missing."""
    plan_data = {"resource_changes": []}

    constants = extract_constant_values(plan_data)

    # Should return empty dict without error
    assert constants == {}


def test_extract_resource_references_from_child_modules():
    """Test extracting references from resources in child modules (submodules)."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.root_bucket",
                        "expressions": {
                            "bucket": {"constant_value": "root-bucket"}
                        }
                    }
                ],
                "child_modules": [
                    {
                        "address": "module.s3_module",
                        "resources": [
                            {
                                "address": "module.s3_module.aws_s3_bucket.example",
                                "expressions": {
                                    "bucket": {"constant_value": "module-bucket"}
                                }
                            },
                            {
                                "address": "module.s3_module.aws_s3_bucket_versioning.example",
                                "expressions": {
                                    "bucket": {
                                        "references": ["module.s3_module.aws_s3_bucket.example.id"]
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }

    references = extract_resource_references(plan_data)

    # Should extract references from both root and child modules
    assert "module.s3_module.aws_s3_bucket.example" in references
    assert "module.s3_module.aws_s3_bucket_versioning.example" in references["module.s3_module.aws_s3_bucket.example"]


def test_extract_resource_references_from_nested_child_modules():
    """Test extracting references from deeply nested child modules."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [],
                "child_modules": [
                    {
                        "address": "module.network",
                        "resources": [
                            {
                                "address": "module.network.aws_vpc.main",
                                "expressions": {}
                            }
                        ],
                        "child_modules": [
                            {
                                "address": "module.network.module.subnets",
                                "resources": [
                                    {
                                        "address": "module.network.module.subnets.aws_subnet.private",
                                        "expressions": {
                                            "vpc_id": {
                                                "references": ["module.network.aws_vpc.main.id"]
                                            }
                                        }
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        }
    }

    references = extract_resource_references(plan_data)

    # Should extract references from nested modules
    assert "module.network.aws_vpc.main" in references
    assert "module.network.module.subnets.aws_subnet.private" in references["module.network.aws_vpc.main"]


def test_extract_constant_values_from_child_modules():
    """Test extracting constant values from resources in child modules."""
    plan_data = {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": "aws_s3_bucket.root",
                        "expressions": {
                            "bucket": {"constant_value": "root-bucket"}
                        }
                    }
                ],
                "child_modules": [
                    {
                        "address": "module.s3_module",
                        "resources": [
                            {
                                "address": "module.s3_module.aws_s3_bucket.example",
                                "expressions": {
                                    "bucket": {"constant_value": "module-bucket-123"}
                                }
                            },
                            {
                                "address": "module.s3_module.aws_s3_bucket_versioning.example",
                                "expressions": {
                                    "bucket": {"constant_value": "module-bucket-123"}
                                }
                            }
                        ]
                    }
                ]
            }
        }
    }

    constants = extract_constant_values(plan_data)

    # Should extract constants from both root and child modules
    assert "aws_s3_bucket.root" in constants
    assert constants["aws_s3_bucket.root"]["bucket"] == "root-bucket"

    assert "module.s3_module.aws_s3_bucket.example" in constants
    assert constants["module.s3_module.aws_s3_bucket.example"]["bucket"] == "module-bucket-123"

    assert "module.s3_module.aws_s3_bucket_versioning.example" in constants
    assert constants["module.s3_module.aws_s3_bucket_versioning.example"]["bucket"] == "module-bucket-123"
