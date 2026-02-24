#!/bin/bash
# Demo: Classify sample IaC changes interactively
# Shows how the SCN detector classifies different types of changes

set -e

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts"
FIXTURES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/tests/fixtures/scn-detector"
DEMO_DIR="/tmp/scn-demo-$$"

mkdir -p "$DEMO_DIR"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  FedRAMP Significant Change Notification (SCN) Detector    ║"
echo "║  Interactive Demo                                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

demo_classification() {
    local name=$1
    local description=$2
    local terraform_code=$3
    local expected_category=$4
    local emoji=$5

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}$emoji  $name${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Description: $description"
    echo ""
    echo "Terraform Change:"
    echo "┌────────────────────────────────────────────────────────┐"
    echo "$terraform_code" | sed 's/^/│ /'
    echo "└────────────────────────────────────────────────────────┘"
    echo ""

    # Create mock change data
    cat > "$DEMO_DIR/change.json" << EOF
{
  "changes": [
    {
      "file": "terraform/example.tf",
      "format": "terraform",
      "resources": [
        {
          "type": "aws_resource",
          "name": "example",
          "operation": "modify",
          "attributes_changed": ["test"],
          "diff": $(echo "$terraform_code" | jq -Rs .)
        }
      ]
    }
  ],
  "summary": {"total_files": 1}
}
EOF

    # Classify
    echo -n "Analyzing... "
    python3 "$SCRIPTS_DIR/classify_changes.py" \
        --input "$DEMO_DIR/change.json" \
        --output "$DEMO_DIR/classification.json" \
        --config "$FIXTURES_DIR/config/scn-config-minimal.yml" \
        > "$DEMO_DIR/classify.log" 2>&1

    # Extract result
    CATEGORY=$(jq -r '.classifications[0].category // "UNKNOWN"' "$DEMO_DIR/classification.json")
    REASONING=$(jq -r '.classifications[0].reasoning // "No reasoning"' "$DEMO_DIR/classification.json")

    if [ "$CATEGORY" == "$expected_category" ]; then
        echo -e "${GREEN}✓ Classified correctly${NC}"
    else
        echo -e "${RED}✗ Unexpected classification${NC}"
    fi

    echo ""
    echo "Result:"
    echo "  Category: $CATEGORY"
    echo "  Reasoning: $REASONING"

    # Show FedRAMP requirements
    case "$CATEGORY" in
        ROUTINE)
            echo ""
            echo -e "${GREEN}FedRAMP Requirement: No notification required${NC}"
            ;;
        ADAPTIVE)
            echo ""
            echo -e "${YELLOW}FedRAMP Requirement: Notify within 10 business days after completion${NC}"
            ;;
        TRANSFORMATIVE)
            echo ""
            echo -e "${RED}FedRAMP Requirement:${NC}"
            echo "  • Initial notice: 30 business days before change"
            echo "  • Final notice: 10 business days before change"
            echo "  • Post-completion: Within 10 business days after"
            ;;
        IMPACT)
            echo ""
            echo -e "${RED}FedRAMP Requirement: New assessment required (cannot use SCN process)${NC}"
            ;;
    esac

    echo ""
    echo "Press Enter to continue..."
    read -r
}

# Demo 1: Routine Change
demo_classification \
    "Routine Change: Tag Update" \
    "Simple tag changes are routine maintenance" \
    'resource "aws_instance" "web" {
  instance_type = "t3.small"

  tags = {
-   Name = "web-server"
+   Name = "web-server-prod"
    Environment = "production"
  }
}' \
    "ROUTINE" \
    "🟢"

# Demo 2: Adaptive Change
demo_classification \
    "Adaptive Change: Instance Type Upgrade" \
    "Like-for-like instance type changes" \
    'resource "aws_instance" "app" {
- instance_type = "t2.micro"
+ instance_type = "t3.small"
  ami           = "ami-12345"
}' \
    "ADAPTIVE" \
    "🟡"

# Demo 3: Transformative Change
demo_classification \
    "Transformative Change: Database Engine" \
    "Major database engine changes alter service architecture" \
    'resource "aws_rds_cluster" "main" {
  cluster_identifier = "prod-db"
- engine            = "postgres"
- engine_version    = "14.7"
+ engine            = "aurora-postgresql"
+ engine_version    = "15.2"
}' \
    "TRANSFORMATIVE" \
    "🟠"

# Demo 4: Impact Change
demo_classification \
    "Impact Change: Encryption Removal" \
    "Encryption changes affect security boundary" \
    'resource "aws_s3_bucket" "data" {
  bucket = "sensitive-data"

- server_side_encryption_configuration {
-   rule {
-     apply_server_side_encryption_by_default {
-       sse_algorithm = "AES256"
-     }
-   }
- }
+ # Encryption removed
}' \
    "IMPACT" \
    "🔴"

# Cleanup
rm -rf "$DEMO_DIR"

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Demo Complete!                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Next Steps:"
echo "  1. Customize rules: Edit .github/scn-config.yml"
echo "  2. Test with real changes: git checkout -b test/scn && edit terraform/"
echo "  3. Run in workflow: See examples/workflows/scn-detection-example.yml"
echo "  4. Enable AI fallback: Add ANTHROPIC_API_KEY secret"
echo ""
