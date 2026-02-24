# Testing Guide for SCN Detector

Comprehensive testing strategy for the FedRAMP Significant Change Notification detector.

## Quick Start

```bash
# 1. Unit tests (fastest, no dependencies)
pytest .github/actions/scn-detector/tests/ -v

# 2. Integration test (requires git repo)
.github/actions/scn-detector/tests/run_integration_test.sh

# 3. Full workflow test (requires GitHub Actions)
# Push to test branch and open PR
```

---

## Level 1: Unit Tests (Local, Fast)

Test individual Python scripts in isolation with mocked dependencies.

### Prerequisites
```bash
pip install pytest pytest-cov pytest-mock PyYAML requests
```

### Run Tests
```bash
# All tests with coverage
pytest .github/actions/scn-detector/tests/ --cov=.github/actions/scn-detector/scripts --cov-report=term-missing -v

# Fast run (no coverage)
pytest .github/actions/scn-detector/tests/ --no-cov -q

# Specific test class
pytest .github/actions/scn-detector/tests/test_classify_changes.py::TestChangeClassifier -v

# Watch mode (requires pytest-watch)
ptw .github/actions/scn-detector/tests/
```

### What Gets Tested
- ✅ Rule matching logic
- ✅ Classification accuracy
- ✅ AI fallback (mocked)
- ✅ Config loading
- ✅ Edge cases

### Example Output
```
test_classify_changes.py::TestChangeClassifier::test_classify_with_rules_routine PASSED
test_classify_changes.py::TestChangeClassifier::test_classify_with_rules_adaptive PASSED
test_classify_changes.py::TestChangeClassifier::test_classify_with_rules_transformative PASSED
test_classify_changes.py::TestChangeClassifier::test_classify_with_rules_impact PASSED

Coverage: 85%
```

---

## Level 2: Script Integration Tests (Local, Real Git)

Test scripts end-to-end with real git operations but without GitHub Actions.

### Setup Test Repository
```bash
# Create a test branch with IaC changes
git checkout -b test/scn-routine-changes

# Add a Terraform file with tag changes (ROUTINE)
cat > terraform/test.tf << 'EOF'
resource "aws_instance" "web" {
  instance_type = "t3.small"

  tags = {
    Name = "test-server"
    Environment = "development"
  }
}
EOF

git add terraform/test.tf
git commit -m "test: Add routine tag changes"
```

### Run Scripts Manually
```bash
# 1. Analyze changes
python3 .github/actions/scn-detector/scripts/analyze_iac_changes.py \
  --base-ref main \
  --head-ref test/scn-routine-changes \
  --output /tmp/iac-changes.json

# Check output
cat /tmp/iac-changes.json | jq .

# 2. Classify changes
python3 .github/actions/scn-detector/scripts/classify_changes.py \
  --input /tmp/iac-changes.json \
  --output /tmp/scn-classifications.json \
  --config .github/scn-config.example.yml

# Check classifications
cat /tmp/scn-classifications.json | jq .summary

# 3. Generate report
python3 .github/actions/scn-detector/scripts/generate_scn_report.py \
  --input /tmp/scn-classifications.json \
  --output-md /tmp/scn-report.md \
  --output-json /tmp/scn-audit.json \
  --repo huntridge-labs/argus \
  --pr-number 999 \
  --run-id 12345 \
  --server-url https://github.com

# View report
cat /tmp/scn-report.md
```

### Test Different Categories

**Adaptive Change (AMI update):**
```bash
git checkout -b test/scn-adaptive-changes

cat > terraform/compute.tf << 'EOF'
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu-22.04-*"]  # Version change
  }
}
EOF

git add terraform/compute.tf
git commit -m "test: Update AMI version"
```

**Transformative Change (Database engine):**
```bash
git checkout -b test/scn-transformative-changes

cat > terraform/database.tf << 'EOF'
resource "aws_rds_cluster" "main" {
  engine = "aurora-postgresql"  # Engine change
  engine_version = "15.2"
}
EOF

git add terraform/database.tf
git commit -m "test: Change database engine"
```

**Impact Change (Remove encryption):**
```bash
git checkout -b test/scn-impact-changes

cat > terraform/storage.tf << 'EOF'
resource "aws_s3_bucket" "data" {
  bucket = "test-data"
  # encryption removed - IMPACT!
}
EOF

git add terraform/storage.tf
git commit -m "test: Remove bucket encryption"
```

---

## Level 3: Action Integration Test (Local with Act)

Test the full composite action using [act](https://github.com/nektos/act) to run GitHub Actions locally.

### Prerequisites
```bash
# Install act
brew install act  # macOS
# or: curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Create local env file
cat > .env.local << 'EOF'
GITHUB_TOKEN=ghp_your_test_token_here
ANTHROPIC_API_KEY=sk-ant-your_key_here  # Optional
EOF
```

### Create Test Workflow
```bash
cat > .github/workflows/test-scn-local.yml << 'EOF'
name: Test SCN Detector (Local)

on: workflow_dispatch

jobs:
  test-scn:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Test SCN Detector
        uses: ./.github/actions/scn-detector
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        with:
          base_ref: 'main'
          head_ref: 'test/scn-routine-changes'
          config_file: '.github/scn-config.example.yml'
          create_issues: false  # Don't create real issues in testing
          post_pr_comment: false
          enable_ai_fallback: false
EOF
```

### Run with Act
```bash
# Run the workflow locally
act workflow_dispatch \
  --workflows .github/workflows/test-scn-local.yml \
  --env-file .env.local \
  --verbose

# Check outputs in act logs
```

---

## Level 4: Full Workflow Test (GitHub Actions)

Test in real GitHub Actions environment with actual PR.

### Setup

1. **Create test configuration:**
```bash
# Use the example as your test config
cp .github/scn-config.example.yml .github/scn-config.yml
git add .github/scn-config.yml
git commit -m "feat: Add SCN config for testing"
git push origin sully/mcn-prototype
```

2. **Add workflow to test branch:**
```yaml
# .github/workflows/test-scn-detector.yml
name: Test SCN Detector

on:
  pull_request:
    branches:
      - sully/mcn-prototype
    paths:
      - 'terraform/**'
      - '.github/actions/scn-detector/**'

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  scn-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0

      - name: Run SCN Detector
        id: scn
        uses: ./.github/actions/scn-detector
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}  # Uncomment to test AI
        with:
          config_file: '.github/scn-config.yml'
          create_issues: true
          post_pr_comment: true
          enable_ai_fallback: false  # Start with rules only

      - name: Verify outputs
        run: |
          echo "Category: ${{ steps.scn.outputs.change_category }}"
          echo "Routine: ${{ steps.scn.outputs.routine_count }}"
          echo "Adaptive: ${{ steps.scn.outputs.adaptive_count }}"
          echo "Transformative: ${{ steps.scn.outputs.transformative_count }}"
          echo "Impact: ${{ steps.scn.outputs.impact_count }}"
          echo "Issues: ${{ steps.scn.outputs.issue_numbers }}"
```

### Test Scenarios

**Scenario 1: Routine Changes**
```bash
git checkout -b test/routine-tags-only
echo 'resource "aws_instance" "test" { tags = { Name = "updated" } }' > terraform/test.tf
git add terraform/test.tf
git commit -m "test: Routine tag change"
git push origin test/routine-tags-only

# Open PR to sully/mcn-prototype
# Expected: 1 routine change, no issues created
```

**Scenario 2: Adaptive Changes**
```bash
git checkout -b test/adaptive-instance-type
cat > terraform/compute.tf << 'EOF'
resource "aws_instance" "app" {
  instance_type = "t3.medium"  # Changed from t2.micro
}
EOF
git add terraform/compute.tf
git commit -m "test: Adaptive instance type change"
git push origin test/adaptive-instance-type

# Open PR
# Expected: 1 adaptive change, 1 issue created with 10-day timeline
```

**Scenario 3: Transformative Changes**
```bash
git checkout -b test/transformative-db-engine
cat > terraform/database.tf << 'EOF'
resource "aws_rds_cluster" "prod" {
  engine = "aurora-postgresql"
  engine_version = "15.2"
}
EOF
git add terraform/database.tf
git commit -m "test: Transformative database engine change"
git push origin test/transformative-db-engine

# Open PR
# Expected: 1 transformative change, issue with 30+10 day timeline
```

**Scenario 4: Impact Changes**
```bash
git checkout -b test/impact-encryption-removal
cat > terraform/storage.tf << 'EOF'
resource "aws_s3_bucket" "sensitive" {
  bucket = "test-data"
  # server_side_encryption_configuration removed
}

resource "aws_security_group" "public" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]  # Public access
  }
}
EOF
git add terraform/storage.tf
git commit -m "test: Impact change - removed encryption"
git push origin test/impact-encryption-removal

# Open PR
# Expected: 2 impact changes, 2 issues with "new assessment required"
```

### Verification Checklist

For each test PR, verify:

- [ ] ✅ PR comment appears with SCN analysis
- [ ] ✅ Change categories are correct
- [ ] ✅ GitHub Issues created for non-routine changes
- [ ] ✅ Issue labels applied correctly (`scn`, `scn:adaptive`, etc.)
- [ ] ✅ Issue timelines calculated correctly
- [ ] ✅ Artifacts uploaded (scn-reports, scn-summary)
- [ ] ✅ Job summary appears in Actions tab
- [ ] ✅ Outputs are set correctly
- [ ] ✅ Workflow passes/fails based on `fail_on_category`

---

## Level 5: AI Fallback Testing

Test the AI classification for ambiguous changes.

### Prerequisites
```bash
# Add Anthropic API key to repository secrets
# Settings → Secrets → Actions → New repository secret
# Name: ANTHROPIC_API_KEY
# Value: sk-ant-...
```

### Test AI Classification
```bash
git checkout -b test/ai-fallback-ambiguous

# Create an ambiguous change (not clearly matching rules)
cat > terraform/custom.tf << 'EOF'
resource "custom_service" "app" {
  configuration = {
    mode = "enhanced"  # Unclear if this is routine, adaptive, or transformative
    security_level = "standard"
  }
}
EOF

git add terraform/custom.tf
git commit -m "test: Ambiguous change for AI classification"
git push origin test/ai-fallback-ambiguous
```

Update workflow to enable AI:
```yaml
- uses: ./.github/actions/scn-detector
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  with:
    enable_ai_fallback: true
```

**Expected behavior:**
- No rule matches → AI fallback triggered
- Claude Haiku analyzes change
- If confidence > 80% → classified
- If confidence < 80% → "Manual Review Required"

---

## Level 6: Performance & Load Testing

Test with large diffs and many changes.

### Bulk Changes Test
```bash
git checkout -b test/bulk-changes

# Create 50 Terraform files with various changes
for i in {1..50}; do
  cat > terraform/resource_$i.tf << EOF
resource "aws_instance" "server_$i" {
  instance_type = "t3.small"
  tags = { Name = "server-$i" }
}
EOF
done

git add terraform/
git commit -m "test: Bulk changes (50 files)"
git push origin test/bulk-changes
```

**Monitor:**
- Action execution time (should be < 5 minutes)
- Memory usage
- AI API costs (if enabled)
- PR comment size (must be < 262KB)

---

## Level 7: Edge Cases & Error Handling

### Empty Diff
```bash
git checkout -b test/no-changes
# Don't make any changes
git push origin test/no-changes

# Expected: "No IaC changes detected"
```

### Malformed Config
```bash
cat > .github/scn-config.yml << 'EOF'
version: "1.0"
rules:
  routine: invalid_yaml_here
EOF

# Expected: Falls back to default rules with warning
```

### Missing Config
```bash
rm .github/scn-config.yml

# Expected: Uses default FedRAMP rules
```

### Binary Files
```bash
echo "binary content" | base64 > terraform/binary.tf

# Expected: Gracefully skips or handles binary files
```

---

## Debugging Failed Tests

### Enable Debug Logging
```yaml
- uses: ./.github/actions/scn-detector
  env:
    ACTIONS_STEP_DEBUG: true
    ACTIONS_RUNNER_DEBUG: true
```

### Check Artifacts
```bash
# Download artifacts from failed runs
gh run download <run-id> --name scn-reports-*

# Inspect files
cat scn-reports/iac-changes.json | jq .
cat scn-reports/scn-classifications.json | jq .
```

### Common Issues

**Issue: "No IaC changes detected"**
```bash
# Fix: Ensure fetch-depth: 0 in checkout
- uses: actions/checkout@v6
  with:
    fetch-depth: 0  # Required!
```

**Issue: "GITHUB_TOKEN not set"**
```yaml
# Fix: Add env variable
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Issue: "Permission denied" on issue creation**
```yaml
# Fix: Add permissions
permissions:
  issues: write
```

---

## CI/CD Integration

### Add to Pre-Commit Hook
```bash
# .git/hooks/pre-commit
#!/bin/bash
pytest .github/actions/scn-detector/tests/ --no-cov -q
```

### Add to PR Checklist
```markdown
## SCN Testing Checklist
- [ ] Unit tests pass locally
- [ ] Integration test with sample IaC changes
- [ ] PR comment generated correctly
- [ ] Issues created with correct labels
- [ ] Artifacts uploaded successfully
```

---

## Next Steps After Testing

1. **Review test results** - Ensure all scenarios pass
2. **Tune configuration** - Adjust rules based on your infrastructure
3. **Train team** - Share SCN categories and timelines
4. **Monitor costs** - If using AI fallback, track API usage
5. **Iterate rules** - Add custom rules for your specific resources

---

## Quick Test Command Reference

```bash
# Unit tests
pytest .github/actions/scn-detector/tests/ -v

# Manual script test
python3 .github/actions/scn-detector/scripts/classify_changes.py \
  --input tests/fixtures/scn-detector/iac-changes.json \
  --output /tmp/test-output.json \
  --config .github/scn-config.example.yml

# Full action test (local with act)
act workflow_dispatch -W .github/workflows/test-scn-detector.yml

# Create test PR
git checkout -b test/scn-$(date +%s)
echo "test" > terraform/test.tf
git add terraform/test.tf
git commit -m "test: SCN detector"
git push origin HEAD
gh pr create --title "Test SCN Detector" --body "Testing SCN classification"
```

---

**Pro Tip:** Start with unit tests → script integration → then full workflows. Fix issues at each level before moving to the next!
