"""Command-line interface for Berm policy engine."""

import atexit
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from berm import __version__
from berm.evaluators.cross_resource import CrossResourceEvaluator
from berm.evaluators.simple import SimpleEvaluator
from berm.loaders.rules import RuleLoadError, load_rules
from berm.loaders.terraform import TerraformPlanLoadError, load_terraform_plan
from berm.models.rule import Rule
from berm.reporters import get_reporter
from berm.security import SecurityError, sanitize_for_output, sanitize_output_path, sanitize_terraform_plan_path

# Track temporary files for cleanup
_temp_files: List[Path] = []


def _cleanup_temp_files() -> None:
    """Clean up temporary files on exit."""
    for temp_file in _temp_files:
        try:
            if temp_file.exists():
                temp_file.unlink()
        except Exception:
            pass  # Ignore cleanup errors


# Register cleanup handler
atexit.register(_cleanup_temp_files)


@click.group()
@click.version_option(version=__version__, prog_name="berm")
def cli() -> None:
    """Berm - Policy Engine for CI/CD Pipelines.

    Guide teams toward infrastructure best practices without blocking velocity.
    """
    pass


@cli.command()
@click.argument("plan_file", type=click.Path(exists=True))
@click.option(
    "--rules-dir",
    "-r",
    default=".berm",
    help="Directory containing policy rules (default: .berm)",
    type=click.Path(exists=True),
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["terminal", "github", "json"], case_sensitive=False),
    default="terminal",
    help="Output format (default: terminal)",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Treat warnings as errors (fail on any violation)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def check(
    plan_file: str,
    rules_dir: str,
    format: str,
    strict: bool,
    verbose: bool,
) -> None:
    """Check a Terraform plan against policy rules.

    PLAN_FILE: Path to Terraform plan JSON file (from 'terraform show -json plan.tfplan')

    Examples:

        berm check plan.json

        berm check plan.json --rules-dir .berm --format github

        berm check plan.json --strict
    """
    exit_code = run_check(plan_file, rules_dir, format, strict, verbose)
    sys.exit(exit_code)


@cli.command()
@click.option(
    "--rules",
    "-r",
    required=True,
    help="Directory containing policy rules",
    type=click.Path(exists=True),
)
@click.option(
    "--plan",
    "-p",
    required=True,
    help="Path to Terraform plan JSON file",
    type=click.Path(exists=True),
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["terminal", "github", "json"], case_sensitive=False),
    default="terminal",
    help="Output format (default: terminal)",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Treat warnings as errors (fail on any violation)",
)
def test(
    rules: str,
    plan: str,
    format: str,
    strict: bool,
) -> None:
    """Test policy rules against a Terraform plan.

    Explicit version of 'check' command for local testing and development.

    Examples:

        berm test --rules examples/rules --plan examples/plans/plan.json

        berm test -r .berm -p plan.json --format json
    """
    exit_code = run_check(plan, rules, format, strict, verbose=False)
    sys.exit(exit_code)


@cli.command()
@click.argument("tfplan_file", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    help="Output JSON file path (default: plan.json)",
    default="plan.json",
    type=click.Path(),
)
def convert(tfplan_file: str, output: str) -> None:
    """Convert a Terraform binary plan to JSON format.

    This is a convenience command that wraps 'terraform show -json'.

    TFPLAN_FILE: Path to Terraform binary plan file (from 'terraform plan -out')

    Examples:

        berm convert plan.tfplan

        berm convert plan.tfplan --output plan.json

    After conversion, you can run:

        berm check plan.json

    SECURITY NOTE: Binary .tfplan files cannot be validated for integrity.
    For production CI/CD, prefer using JSON plans directly:
        terraform show -json plan.tfplan > plan.json
        berm check plan.json
    """
    try:
        # Warn about binary plan security risks
        if tfplan_file.endswith('.tfplan'):
            click.echo(
                "WARNING: Converting binary .tfplan file. Binary plan files cannot be "
                "validated for integrity. For production use, prefer JSON plans.",
                err=True
            )

        # Validate input path (prevents path traversal)
        try:
            validated_input = sanitize_terraform_plan_path(tfplan_file)
        except (SecurityError, ValueError) as e:
            safe_error = sanitize_for_output(str(e), context="terminal")
            click.echo(f"Error: Invalid input path - {safe_error}", err=True)
            sys.exit(2)

        # Validate output path (prevents path traversal and arbitrary file write)
        try:
            validated_output = sanitize_output_path(output)
        except (SecurityError, ValueError) as e:
            safe_error = sanitize_for_output(str(e), context="terminal")
            click.echo(f"Error: Invalid output path - {safe_error}", err=True)
            sys.exit(2)

        # Run terraform show -json with validated paths
        # Use str() to convert Path objects to strings for subprocess
        result = subprocess.run(
            ["terraform", "show", "-json", str(validated_input)],
            capture_output=True,
            text=True,
            check=True,
            timeout=300,  # 5 minute timeout
        )

        # Write output to file with proper encoding (no BOM)
        with open(validated_output, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        click.echo(f"✓ Converted {tfplan_file} to {output}")
        click.echo(f"  Run: berm check {output}")
        sys.exit(0)

    except FileNotFoundError:
        click.echo(
            "Error: terraform command not found. Make sure Terraform is installed and in your PATH.",
            err=True,
        )
        sys.exit(2)

    except subprocess.TimeoutExpired:
        click.echo(
            "Error: terraform show command timed out after 5 minutes.",
            err=True,
        )
        sys.exit(2)

    except subprocess.CalledProcessError as e:
        click.echo(f"Error running terraform show: {e.stderr}", err=True)
        sys.exit(2)

    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(2)


@cli.command()
@click.option(
    "--dir",
    "-d",
    default=".berm",
    help="Directory to create for rules (default: .berm)",
    type=click.Path(),
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing directory if it exists",
)
def init(dir: str, force: bool) -> None:
    """Initialize a new rules directory with example rules.

    Creates a rules directory with example policy rules for common AWS resources.

    Examples:

        berm init

        berm init --dir policies

        berm init --force  # Overwrite existing .berm directory
    """
    console = Console()

    try:
        target_dir = Path(dir)

        # Check if directory exists
        if target_dir.exists():
            if not force:
                console.print(f"[red]Error: Directory '{dir}' already exists.[/red]")
                console.print(f"Use --force to overwrite or choose a different directory.")
                sys.exit(1)
            else:
                console.print(f"[yellow]Removing existing directory '{dir}'...[/yellow]")
                shutil.rmtree(target_dir)

        # Create directory
        target_dir.mkdir(parents=True, exist_ok=True)

        # Define example rules
        example_rules = {
            "s3-versioning-enabled.json": {
                "id": "s3-versioning-enabled",
                "name": "S3 buckets must have versioning enabled",
                "resource_type": "aws_s3_bucket",
                "severity": "error",
                "property": "versioning.0.enabled",
                "equals": True,
                "message": "S3 bucket {{resource_name}} must have versioning enabled"
            },
            "s3-encryption-enabled.json": {
                "id": "s3-encryption-enabled",
                "name": "S3 buckets must have encryption enabled",
                "resource_type": "aws_s3_bucket",
                "severity": "error",
                "property": "server_side_encryption_configuration.0.rule.0.apply_server_side_encryption_by_default.0.sse_algorithm",
                "in": ["AES256", "aws:kms"],
                "message": "S3 bucket {{resource_name}} must have server-side encryption enabled"
            },
            "ec2-allowed-instance-types.json": {
                "id": "ec2-allowed-instance-types",
                "name": "EC2 instances must use approved instance types",
                "resource_type": "aws_instance",
                "severity": "error",
                "property": "instance_type",
                "in": ["t3.micro", "t3.small", "t3.medium", "t3.large"],
                "message": "EC2 instance {{resource_name}} must use an approved instance type"
            },
            "rds-backup-retention.json": {
                "id": "rds-backup-retention",
                "name": "RDS instances should have minimum backup retention",
                "resource_type": "aws_db_instance",
                "severity": "warning",
                "property": "backup_retention_period",
                "greater_than_or_equal": 7,
                "message": "RDS instance {{resource_name}} should have at least 7 days backup retention"
            },
            "s3-bucket-name-pattern.json": {
                "id": "s3-bucket-name-pattern",
                "name": "S3 bucket names must follow naming convention",
                "resource_type": "aws_s3_bucket",
                "severity": "error",
                "property": "bucket",
                "regex_match": "^[a-z0-9][a-z0-9-]*[a-z0-9]$",
                "message": "S3 bucket {{resource_name}} must use lowercase alphanumeric characters and hyphens only"
            }
        }

        # Write example rules
        for filename, rule_content in example_rules.items():
            rule_path = target_dir / filename
            with open(rule_path, "w", encoding="utf-8") as f:
                json.dump(rule_content, f, indent=2)
                f.write("\n")  # Add trailing newline

        # Success message
        console.print(Panel.fit(
            f"[green]Success! Initialized rules directory:[/green] [bold]{dir}[/bold]\n\n"
            f"Created {len(example_rules)} example rules:\n"
            + "\n".join(f"  - {filename}" for filename in example_rules.keys()) + "\n\n"
            f"[dim]Next steps:[/dim]\n"
            f"  1. Review and customize the rules\n"
            f"  2. Run: [bold]berm check plan.json[/bold]",
            title="Berm Initialized",
            border_style="green"
        ))
        sys.exit(0)

    except Exception as e:
        console.print(f"[red]Error initializing rules directory: {e}[/red]")
        sys.exit(2)


@cli.command()
@click.option(
    "--rules-dir",
    "-r",
    default=".berm",
    help="Directory containing policy rules (default: .berm)",
    type=click.Path(exists=True),
)
def validate_rules(rules_dir: str) -> None:
    """Validate policy rules without running them.

    Checks that all rule files are valid JSON and conform to the rule schema.

    Examples:

        berm validate-rules

        berm validate-rules --rules-dir policies
    """
    console = Console()

    try:
        console.print(f"[cyan]Validating rules in:[/cyan] {rules_dir}")

        # Load rules (this will validate them)
        rules = load_rules(rules_dir)

        # Success
        console.print(Panel.fit(
            f"[green]Success! All rules are valid![/green]\n\n"
            f"Validated {len(rules)} rule(s):\n"
            + "\n".join(f"  - {rule.id}: {rule.name}" for rule in rules),
            title="Validation Successful",
            border_style="green"
        ))
        sys.exit(0)

    except RuleLoadError as e:
        safe_error = sanitize_for_output(str(e), context="terminal")
        console.print(f"[red]Rule validation failed:[/red]\n{safe_error}")
        sys.exit(1)

    except Exception as e:
        safe_error = sanitize_for_output(str(e), context="terminal")
        console.print(f"[red]Error: {safe_error}[/red]")
        sys.exit(2)


@cli.command()
@click.argument("rule_id")
@click.option(
    "--rules-dir",
    "-r",
    default=".berm",
    help="Directory containing policy rules (default: .berm)",
    type=click.Path(exists=True),
)
def explain(rule_id: str, rules_dir: str) -> None:
    """Explain what a specific rule checks.

    Shows detailed information about a rule including its purpose,
    resource type, comparison logic, and severity.

    Examples:

        berm explain s3-versioning-enabled

        berm explain rds-backup-retention --rules-dir policies
    """
    console = Console()

    try:
        # Load rules
        rules = load_rules(rules_dir)

        # Find the rule
        rule = None
        for r in rules:
            if r.id == rule_id:
                rule = r
                break

        if rule is None:
            console.print(f"[red]Error: Rule '{rule_id}' not found.[/red]")
            console.print(f"\nAvailable rules:")
            for r in rules:
                console.print(f"  - {r.id}")
            sys.exit(1)

        # Display rule details
        severity_color = "red" if rule.severity == "error" else "yellow"

        # Determine operator description
        operator_info = ""
        if rule.resource_forbidden:
            operator_info = "[red]Forbidden Resource[/red]\nAny usage of this resource type is not allowed."
        elif rule.equals is not None:
            operator_info = f"Property must equal: [cyan]{rule.equals}[/cyan]"
        elif rule.greater_than is not None:
            operator_info = f"Property must be greater than: [cyan]{rule.greater_than}[/cyan]"
        elif rule.greater_than_or_equal is not None:
            operator_info = f"Property must be >= [cyan]{rule.greater_than_or_equal}[/cyan]"
        elif rule.less_than is not None:
            operator_info = f"Property must be less than: [cyan]{rule.less_than}[/cyan]"
        elif rule.less_than_or_equal is not None:
            operator_info = f"Property must be <= [cyan]{rule.less_than_or_equal}[/cyan]"
        elif rule.contains is not None:
            operator_info = f"Property must contain: [cyan]{rule.contains}[/cyan]"
        elif rule.in_list is not None:
            operator_info = f"Property must be one of: [cyan]{rule.in_list}[/cyan]"
        elif rule.regex_match is not None:
            operator_info = f"Property must match pattern: [cyan]{rule.regex_match}[/cyan]"

        content = f"""[bold]{rule.name}[/bold]

[dim]Rule ID:[/dim] {rule.id}
[dim]Severity:[/dim] [{severity_color}]{rule.severity.upper()}[/{severity_color}]
[dim]Resource Type:[/dim] {rule.resource_type}
"""

        if rule.property:
            content += f"[dim]Property Path:[/dim] {rule.property}\n"

        content += f"\n[bold]Check:[/bold]\n{operator_info}\n"
        content += f"\n[bold]Violation Message:[/bold]\n{rule.message}"

        console.print(Panel(
            content,
            title=f"Rule: {rule.id}",
            border_style=severity_color
        ))
        sys.exit(0)

    except RuleLoadError as e:
        safe_error = sanitize_for_output(str(e), context="terminal")
        console.print(f"[red]Error loading rules: {safe_error}[/red]")
        sys.exit(2)

    except Exception as e:
        safe_error = sanitize_for_output(str(e), context="terminal")
        console.print(f"[red]Error: {safe_error}[/red]")
        sys.exit(2)


def run_check(
    plan_file: str,
    rules_dir: str,
    format: str,
    strict: bool,
    verbose: bool,
) -> int:
    """Run policy checks and return exit code.

    Args:
        plan_file: Path to Terraform plan JSON
        rules_dir: Directory containing rule files
        format: Output format (terminal, github, json)
        strict: Treat warnings as errors
        verbose: Enable verbose output

    Returns:
        Exit code: 0 = pass, 1 = violations found, 2 = error
    """
    try:
        # Load rules
        if verbose:
            click.echo(f"Loading rules from: {rules_dir}")

        rules = load_rules(rules_dir)

        if verbose:
            click.echo(f"Loaded {len(rules)} rule(s)")

        # Auto-detect and convert binary plan files
        plan_file = _ensure_json_plan(plan_file, verbose)

        # Check if any rules need deletions
        include_deletions = any(
            rule.detect_destructive_actions for rule in rules
        )

        # Load Terraform plan
        if verbose:
            click.echo(f"Loading Terraform plan: {plan_file}")
            if include_deletions:
                click.echo("Including deleted resources for destructive action detection")

        resources = load_terraform_plan(plan_file, include_deletions=include_deletions)

        if verbose:
            click.echo(f"Loaded {len(resources)} resource(s)")

        # Load full plan data for cross-resource validation
        # We need the configuration section for reference tracking
        plan_data = None
        try:
            with open(plan_file, "r", encoding="utf-8-sig") as f:
                plan_data = json.load(f)
        except Exception:
            # If we can't load plan data, cross-resource validation will degrade gracefully
            pass

        # Evaluate rules
        if verbose:
            click.echo("Evaluating policy rules...")

        # Use both evaluators
        simple_evaluator = SimpleEvaluator()
        cross_evaluator = CrossResourceEvaluator()

        violations = []
        for rule in rules:
            # Simple property-based evaluation
            violations.extend(simple_evaluator.evaluate(rule, resources))

            # Cross-resource relationship evaluation
            violations.extend(cross_evaluator.evaluate(rule, resources, plan_data))

        # Report violations
        reporter = get_reporter(format)
        reporter.report(violations)

        # Determine exit code
        errors = [v for v in violations if v.is_error()]
        warnings = [v for v in violations if v.is_warning()]

        if errors:
            # Errors found - fail
            return 1
        elif warnings and strict:
            # Warnings in strict mode - fail
            return 1
        else:
            # No violations or only warnings in non-strict mode - pass
            return 0

    except RuleLoadError as e:
        safe_error = sanitize_for_output(str(e), context="terminal")
        click.echo(f"Error loading rules: {safe_error}", err=True)
        return 2

    except TerraformPlanLoadError as e:
        safe_error = sanitize_for_output(str(e), context="terminal")
        click.echo(f"Error loading Terraform plan: {safe_error}", err=True)
        return 2

    except Exception as e:
        # Sanitize error messages to prevent information disclosure
        safe_error = sanitize_for_output(str(e), context="terminal")
        click.echo(f"Unexpected error: {safe_error}", err=True)
        if verbose:
            import traceback
            import io
            # Capture traceback and sanitize it
            tb_output = io.StringIO()
            traceback.print_exc(file=tb_output)
            tb_text = tb_output.getvalue()
            # Sanitize the traceback
            safe_tb = sanitize_for_output(tb_text, context="terminal")
            click.echo(safe_tb, err=True)
        return 2


def _ensure_json_plan(plan_file: str, verbose: bool) -> str:
    """Ensure plan file is JSON format, auto-converting binary plans if needed.

    Args:
        plan_file: Path to plan file (JSON or binary)
        verbose: Whether to output conversion messages

    Returns:
        Path to JSON plan file (original or converted temp file)
    """
    # Validate the input path first
    try:
        validated_path = sanitize_terraform_plan_path(plan_file)
    except (SecurityError, ValueError) as e:
        raise TerraformPlanLoadError(f"Invalid plan file path: {e}")

    # Try to detect if this is a JSON file
    try:
        with open(validated_path, "r", encoding="utf-8-sig") as f:
            json.load(f)
        # It's valid JSON, return as-is
        return plan_file
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not JSON or binary file - try to convert
        if verbose:
            click.echo(
                f"Detected binary plan file, converting to JSON using 'terraform show'..."
            )

        try:
            # Convert to JSON using terraform show with validated path
            result = subprocess.run(
                ["terraform", "show", "-json", str(validated_path)],
                capture_output=True,
                text=True,
                check=True,
                timeout=300,  # 5 minute timeout
            )

            # Write to temporary file with proper encoding (no BOM)
            temp_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            )
            temp_file.write(result.stdout)
            temp_file.close()

            # Track for cleanup
            temp_path = Path(temp_file.name)
            _temp_files.append(temp_path)

            if verbose:
                click.echo(f"✓ Converted to temporary JSON file: {temp_file.name}")

            return temp_file.name

        except FileNotFoundError:
            raise TerraformPlanLoadError(
                "Binary plan file detected but 'terraform' command not found. "
                "Either install Terraform or convert the plan manually: "
                f"terraform show -json {plan_file} > plan.json"
            )
        except subprocess.TimeoutExpired:
            raise TerraformPlanLoadError(
                "Terraform show command timed out after 5 minutes"
            )
        except subprocess.CalledProcessError as e:
            raise TerraformPlanLoadError(
                f"Failed to convert binary plan file: {e.stderr}"
            )


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
