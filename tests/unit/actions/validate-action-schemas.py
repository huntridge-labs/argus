#!/usr/bin/env python3
"""Validate composite action schemas"""

import sys
from pathlib import Path
import yaml

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
NC = '\033[0m'

tests_passed = 0
tests_failed = 0


def assert_pass(test_name: str):
    global tests_passed
    print(f"{GREEN}✓{NC} PASS: {test_name}")
    tests_passed += 1


def assert_fail(test_name: str, reason: str = "Unknown failure"):
    global tests_failed
    print(f"{RED}✗{NC} FAIL: {test_name}")
    print(f"  Reason: {reason}")
    tests_failed += 1


def validate_action(action_file: Path):
    """Validate a single action.yml file"""
    action_name = action_file.parent.name

    # Test: action file is valid YAML
    try:
        with open(action_file) as f:
            action = yaml.safe_load(f)
    except Exception as e:
        assert_fail(f"[{action_name}] Valid YAML syntax", str(e))
        return
    assert_pass(f"[{action_name}] Valid YAML syntax")

    # Test: has required 'name' field
    if not action.get('name'):
        assert_fail(f"[{action_name}] Has 'name' field")
    else:
        assert_pass(f"[{action_name}] Has 'name' field")

    # Test: has 'description' field
    if not action.get('description'):
        assert_fail(f"[{action_name}] Has 'description' field")
    else:
        assert_pass(f"[{action_name}] Has 'description' field")

    # Test: has 'runs' section
    runs = action.get('runs')
    if not runs:
        assert_fail(f"[{action_name}] Has 'runs' section")
        return
    assert_pass(f"[{action_name}] Has 'runs' section")

    # Test: runs.using is 'composite'
    using = runs.get('using')
    if using != 'composite':
        assert_fail(f"[{action_name}] runs.using is 'composite' (got: {using})")
    else:
        assert_pass(f"[{action_name}] runs.using is 'composite'")

    # Test: has steps in runs section
    steps = runs.get('steps', [])
    if not steps:
        assert_fail(f"[{action_name}] Has at least one step")
    else:
        assert_pass(f"[{action_name}] Has {len(steps)} steps")

    # Test: all inputs have descriptions
    inputs = action.get('inputs', {})
    if inputs:
        all_inputs_valid = True
        for input_name, input_spec in inputs.items():
            if not input_spec.get('description'):
                assert_fail(f"[{action_name}] Input '{input_name}' has description")
                all_inputs_valid = False

        if all_inputs_valid:
            assert_pass(f"[{action_name}] All {len(inputs)} inputs have descriptions")

    # Test: all outputs have descriptions
    outputs = action.get('outputs', {})
    if outputs:
        all_outputs_valid = True
        for output_name, output_spec in outputs.items():
            if not output_spec.get('description'):
                assert_fail(f"[{action_name}] Output '{output_name}' has description")
                all_outputs_valid = False

        if all_outputs_valid:
            assert_pass(f"[{action_name}] All {len(outputs)} outputs have descriptions")

    # Test: each step with 'run' has a shell specified
    for i, step in enumerate(steps, 1):
        # Only check steps that use 'run' (not 'uses')
        if 'run' in step and 'shell' not in step:
            step_name = step.get('name', f'step {i}')
            assert_fail(f"[{action_name}] Step {i} ('{step_name}') with 'run' has shell specified")
            break

    print()


def main():
    print("Validating Composite Action Schemas")
    print("====================================")

    repo_root = Path(__file__).parent.parent.parent.parent
    actions_dir = repo_root / ".github" / "actions"

    if not actions_dir.exists():
        print(f"{RED}Actions directory not found: {actions_dir}{NC}")
        sys.exit(1)

    # Find all action.yml files
    action_files = list(actions_dir.glob("*/action.yml"))
    action_files.extend(actions_dir.glob("*/action.yaml"))

    if not action_files:
        print(f"{RED}No action files found in {actions_dir}{NC}")
        sys.exit(1)

    print(f"Found {len(action_files)} action files to validate")
    print()

    # Validate each action
    for action_file in sorted(action_files):
        validate_action(action_file)

    # Print summary
    print("=" * 38)
    print(f"Tests passed: {tests_passed}")
    print(f"Tests failed: {tests_failed}")
    print("=" * 38)

    if tests_failed == 0:
        print(f"{GREEN}All tests passed!{NC}")
        sys.exit(0)
    else:
        print(f"{RED}Some tests failed{NC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
