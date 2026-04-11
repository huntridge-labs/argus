"""Pytest tests for composite action schema validation.

Validates the same rules as validate-action-schemas.py but uses pytest
assertions instead of sys.exit(). The original script is kept for the
`npm run validate` command.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).parent.parent.parent.parent
ACTIONS_DIR = REPO_ROOT / ".github" / "actions"


def _discover_action_files():
    """Find all action.yml / action.yaml files under .github/actions/."""
    files = sorted(ACTIONS_DIR.glob("*/action.yml"))
    files.extend(sorted(ACTIONS_DIR.glob("*/action.yaml")))
    return files


# Discover once at import time so parametrize works
ACTION_FILES = _discover_action_files()


class TestActionDiscovery:
    """Ensure the actions directory exists and contains action files."""

    def test_actions_directory_exists(self):
        assert ACTIONS_DIR.exists(), f"Actions directory not found: {ACTIONS_DIR}"

    def test_action_files_found(self):
        assert len(ACTION_FILES) > 0, f"No action files found in {ACTIONS_DIR}"


@pytest.mark.parametrize(
    "action_file",
    ACTION_FILES,
    ids=[f.parent.name for f in ACTION_FILES],
)
class TestActionSchema:
    """Validate structure of each composite action definition."""

    def test_valid_yaml_syntax(self, action_file):
        """Action file must be valid YAML."""
        with open(action_file) as f:
            yaml.safe_load(f)

    def test_has_name_field(self, action_file):
        """Action must have a non-empty 'name' field."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        assert action.get('name'), f"Missing or empty 'name' in {action_file}"

    def test_has_description_field(self, action_file):
        """Action must have a non-empty 'description' field."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        assert action.get('description'), f"Missing or empty 'description' in {action_file}"

    def test_has_runs_section(self, action_file):
        """Action must have a 'runs' section."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        assert action.get('runs'), f"Missing 'runs' section in {action_file}"

    def test_runs_using_is_composite(self, action_file):
        """runs.using must be 'composite'."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        runs = action.get('runs', {})
        assert runs.get('using') == 'composite', (
            f"runs.using is '{runs.get('using')}', expected 'composite' in {action_file}"
        )

    def test_has_at_least_one_step(self, action_file):
        """Action must have at least one step in runs.steps."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        steps = action.get('runs', {}).get('steps', [])
        assert len(steps) > 0, f"No steps defined in {action_file}"

    def test_all_inputs_have_descriptions(self, action_file):
        """Every declared input must have a non-empty description."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        inputs = action.get('inputs', {})
        if not inputs:
            pytest.skip("No inputs declared")
        missing = [
            name for name, spec in inputs.items()
            if not spec.get('description')
        ]
        assert not missing, (
            f"Inputs missing descriptions in {action_file.parent.name}: {missing}"
        )

    def test_all_outputs_have_descriptions(self, action_file):
        """Every declared output must have a non-empty description."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        outputs = action.get('outputs', {})
        if not outputs:
            pytest.skip("No outputs declared")
        missing = [
            name for name, spec in outputs.items()
            if not spec.get('description')
        ]
        assert not missing, (
            f"Outputs missing descriptions in {action_file.parent.name}: {missing}"
        )

    def test_run_steps_have_shell_specified(self, action_file):
        """Every step with a 'run' key must also specify 'shell'."""
        with open(action_file) as f:
            action = yaml.safe_load(f)
        steps = action.get('runs', {}).get('steps', [])
        violations = []
        for i, step in enumerate(steps, 1):
            if 'run' in step and 'shell' not in step:
                step_name = step.get('name', f'step {i}')
                violations.append(f"Step {i} ('{step_name}')")
        assert not violations, (
            f"Steps with 'run' but no 'shell' in {action_file.parent.name}: {violations}"
        )
