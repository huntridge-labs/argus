#!/bin/bash
# Quick integration test for SCN detector
# Tests all 4 classification categories with real fixtures

set -e

echo "🧪 SCN Detector Quick Test"
echo "=========================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/tests/fixtures/scn-detector"
TEMP_DIR="/tmp/scn-test-$$"

mkdir -p "$TEMP_DIR"

echo "📂 Test directory: $TEMP_DIR"
echo ""

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

test_classification() {
    local category=$1
    local fixture=$2
    local expected_category=$3

    echo "Test: $category"
    echo "  Fixture: $fixture"

    # Create mock iac-changes.json from fixture
    cat > "$TEMP_DIR/iac-changes-$category.json" << EOF
{
  "changes": [
    {
      "file": "$fixture",
      "format": "terraform",
      "resources": [
        {
          "type": "test_resource",
          "name": "test",
          "operation": "modify",
          "attributes_changed": ["test"],
          "diff": "$(cat "$FIXTURES_DIR/iac-changes/$fixture" | head -20 | sed 's/"/\\"/g' | tr '\n' ' ')"
        }
      ]
    }
  ],
  "summary": {
    "total_files": 1,
    "terraform_files": 1
  }
}
EOF

    # Run classification
    if python3 "$SCRIPTS_DIR/classify_changes.py" \
        --input "$TEMP_DIR/iac-changes-$category.json" \
        --output "$TEMP_DIR/classifications-$category.json" \
        --config "$FIXTURES_DIR/config/scn-config-minimal.yml" \
        2>&1 | grep -q "$expected_category"; then

        echo -e "  ${GREEN}✓ PASSED${NC} - Classified as $expected_category"
        ((TESTS_PASSED++))
    else
        echo -e "  ${RED}✗ FAILED${NC} - Expected $expected_category"
        ((TESTS_FAILED++))
    fi

    echo ""
}

# Test 1: Routine changes (tags only)
test_classification "ROUTINE" "terraform-routine.diff" "ROUTINE"

# Test 2: Adaptive changes (instance type)
test_classification "ADAPTIVE" "terraform-adaptive.diff" "ADAPTIVE"

# Test 3: Transformative changes (database engine)
test_classification "TRANSFORMATIVE" "terraform-transformative.diff" "TRANSFORMATIVE"

# Test 4: Impact changes (encryption removal)
test_classification "IMPACT" "terraform-impact.diff" "IMPACT"

# Summary
echo "=========================="
echo "Test Results:"
echo -e "  ${GREEN}Passed: $TESTS_PASSED${NC}"
if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "  ${RED}Failed: $TESTS_FAILED${NC}"
else
    echo -e "  ${GREEN}Failed: 0${NC}"
fi
echo ""

# Cleanup
rm -rf "$TEMP_DIR"

if [ $TESTS_FAILED -gt 0 ]; then
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
else
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Run full test suite: pytest .github/actions/scn-detector/tests/ -v"
    echo "  2. Test with real git diff: See TESTING.md Level 2"
    echo "  3. Test in GitHub Actions: See TESTING.md Level 4"
    exit 0
fi
