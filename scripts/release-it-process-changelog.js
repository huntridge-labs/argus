#!/usr/bin/env node
/**
 * Post-process changelog to categorize dependency updates
 *
 * This script:
 * 1. Reads the generated CHANGELOG.md
 * 2. Filters out non-deps commits from Maintenance section
 * 3. Categorizes deps commits into Security Tools vs Dependencies
 */

const fs = require('fs');
const path = require('path');

// Security scanner patterns to detect in commit messages
const securityScannerPatterns = [
  'bridgecrewio/checkov-action',
  'checkov-action',
  'checkov',
  'aquasecurity/trivy-action',
  'trivy-action',
  'trivy',
  'anchore/sbom-action',
  'sbom-action',
  'syft',
  'anchore/scan-action',
  'grype',
  'clamav',
  'gitleaks/gitleaks-action',
  'gitleaks-action',
  'gitleaks',
  'bandit',
  'opengrep',
  'semgrep',
  'github/codeql-action',
  'codeql-action',
  'codeql'
];

function isSecurityScanner(commitText) {
  const lowerText = commitText.toLowerCase();
  return securityScannerPatterns.some(pattern =>
    lowerText.includes(pattern.toLowerCase())
  );
}

function processChangelog(changelogFile = 'CHANGELOG.md') {
  const changelogPath = path.join(process.cwd(), changelogFile);

  if (!fs.existsSync(changelogPath)) {
    console.log('CHANGELOG.md not found, skipping processing');
    return;
  }

  let content = fs.readFileSync(changelogPath, 'utf8');
  const originalContent = content;

  // Find Maintenance sections and process them
  // Match "### Maintenance" followed by content until next "###" or end
  // Handle both single and double newlines after the heading
  const maintenancePattern = /### Maintenance\n+([^]*?)(?=\n###|\n##|$)/g;

  let replacementCount = 0;
  content = content.replace(maintenancePattern, (match, maintenanceContent) => {
    replacementCount++;
    console.log(`Processing Maintenance section #${replacementCount}`);
    // Extract all commit lines (lines starting with *)
    const commits = maintenanceContent.match(/^\* .+$/gm) || [];
    console.log(`Found ${commits.length} commits in section`);

    const securityToolCommits = [];
    const dependencyCommits = [];

    // Filter and categorize commits
    const otherMaintenanceCommits = [];

    commits.forEach(commit => {
      // Match pattern: * **<scope>:** or * **<scope>**:
      // Handle both correct format (deps**:) and malformed (deps)(deps:)
      const scopeMatch = commit.match(/^\* \*\*([^:]+):/);

      if (!scopeMatch) {
        return; // No scope found, skip this commit
      }

      const scope = scopeMatch[1];

      // Only process commits where scope contains 'deps'
      if (!scope.includes('deps')) {
        otherMaintenanceCommits.push(commit);
        return; // Not a deps commit, keep in Maintenance
      }

      // Categorize deps commits
      if (isSecurityScanner(commit)) {
        securityToolCommits.push(commit);
      } else {
        dependencyCommits.push(commit);
      }
    });

    console.log(`  Security Tools: ${securityToolCommits.length}, Dependencies: ${dependencyCommits.length}, Other Maintenance: ${otherMaintenanceCommits.length}`);

    // Build replacement sections
    let replacement = '';

    if (securityToolCommits.length > 0) {
      replacement += '### Security Tools\n\n';
      replacement += securityToolCommits.join('\n') + '\n\n';
    }

    if (dependencyCommits.length > 0) {
      replacement += '### Dependencies\n\n';
      replacement += dependencyCommits.join('\n') + '\n\n';
    }

    if (otherMaintenanceCommits.length > 0) {
      replacement += '### Maintenance\n\n';
      replacement += otherMaintenanceCommits.join('\n') + '\n\n';
    }

    // If no commits left after filtering, remove the section entirely
    if (replacement === '') {
      return '';
    }

    return replacement.trim() + '\n\n';
  });

  // Write back only if content changed
  if (content !== originalContent) {
    fs.writeFileSync(changelogPath, content);
    console.log(`✓ Processed ${changelogFile} - categorized dependency updates (${replacementCount} sections processed)`);
  } else {
    console.log(`ℹ No Maintenance sections found or no changes needed in ${changelogFile}`);
  }
}

// Run if called directly
if (require.main === module) {
  // Get changelog file from command line argument or use default
  const changelogFile = process.argv[2] || 'CHANGELOG.md';
  processChangelog(changelogFile);
}

module.exports = { processChangelog };
