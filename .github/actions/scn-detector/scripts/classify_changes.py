#!/usr/bin/env python3
"""
FedRAMP SCN Detector - Change Classification Engine

Classifies IaC changes into FedRAMP SCN categories using:
1. Rule-based pattern matching (fast, deterministic)
2. AI fallback with Claude Haiku (for ambiguous cases)

Categories:
- ROUTINE: No notification required
- ADAPTIVE: Within 10 business days after completion
- TRANSFORMATIVE: 30 days initial + 10 days final + after
- IMPACT: New assessment required
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml
import requests

# Try importing anthropic SDK (optional)
try:
    from anthropic import Anthropic
    HAS_ANTHROPIC_SDK = True
except ImportError:
    HAS_ANTHROPIC_SDK = False


class ChangeClassifier:
    """Classifies IaC changes according to FedRAMP SCN guidelines."""

    # Default FedRAMP-aligned rules (used when no config provided)
    DEFAULT_RULES = {
        'routine': [
            {'pattern': r'tags\.*', 'description': 'Tag changes'},
            {'pattern': r'description', 'description': 'Description changes'},
        ],
        'adaptive': [
            {'resource': r'aws_ami\..*', 'operation': 'modify', 'description': 'AMI updates'},
            {'resource': r'aws_instance\..*\.instance_type', 'operation': 'modify', 'description': 'Instance type changes'},
        ],
        'transformative': [
            {'pattern': r'provider\..*\.region', 'operation': 'modify', 'description': 'Region changes'},
            {'resource': r'aws_rds_.*\.engine', 'operation': 'modify', 'description': 'Database engine changes'},
        ],
        'impact': [
            {'attribute': r'.*encryption.*', 'operation': 'delete|modify', 'description': 'Encryption changes'},
            {'resource': r'aws_security_group\..*', 'attribute': r'ingress', 'pattern': r'0\.0\.0\.0/0', 'description': 'Public security group'},
        ]
    }

    DEFAULT_AI_CONFIG = {
        'enabled': True,
        'model': 'claude-3-haiku-20240307',
        'confidence_threshold': 0.8,
        'max_tokens': 1024
    }

    def __init__(self, config: Optional[Dict] = None, enable_ai: bool = False, api_key: Optional[str] = None):
        """
        Initialize classifier.

        Args:
            config: Configuration dictionary (or None for defaults)
            enable_ai: Whether to enable AI fallback
            api_key: Anthropic API key (or None to use env var)
        """
        self.config = config or {}
        self.rules = self.config.get('rules', self.DEFAULT_RULES)
        self.ai_config = self.config.get('ai_fallback', self.DEFAULT_AI_CONFIG)
        self.enable_ai = enable_ai and self.ai_config.get('enabled', True)
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')

        # Initialize Anthropic client if AI enabled
        if self.enable_ai:
            if HAS_ANTHROPIC_SDK:
                self.anthropic_client = Anthropic(api_key=self.api_key) if self.api_key else None
            else:
                self.anthropic_client = None

    def load_config_from_file(self, config_path: str) -> Dict:
        """
        Load configuration from YAML file.

        Args:
            config_path: Path to config YAML

        Returns:
            Configuration dictionary
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                print(f"✅ Loaded config from {config_path}")
                return config
        except FileNotFoundError:
            print(f"⚠️  Config file not found: {config_path}", file=sys.stderr)
            print("📝 Using default FedRAMP rules", file=sys.stderr)
            return {}
        except yaml.YAMLError as e:
            print(f"❌ Invalid YAML in config file: {e}", file=sys.stderr)
            return {}

    def match_rule(self, change: Dict, rule: Dict) -> bool:
        """
        Check if a change matches a rule.

        Args:
            change: Change dictionary with resource info
            rule: Rule dictionary with matching criteria

        Returns:
            True if rule matches
        """
        resource_type = change.get('type', '')
        resource_name = change.get('name', '')
        operation = change.get('operation', '')
        attributes = change.get('attributes_changed', [])
        diff = change.get('diff', '')

        # Check pattern (matches resource name, type, or attributes)
        if 'pattern' in rule:
            pattern = rule['pattern']
            match_text = f"{resource_type}.{resource_name} {' '.join(attributes)} {diff}"
            if not re.search(pattern, match_text, re.IGNORECASE):
                return False

        # Check resource type/name pattern
        if 'resource' in rule:
            resource_pattern = rule['resource']
            full_resource = f"{resource_type}.{resource_name}"

            # Check if pattern matches type.name or type.name.attribute
            matched = re.search(resource_pattern, full_resource, re.IGNORECASE)

            # If not matched and pattern contains more dots, check with attributes
            if not matched and resource_pattern.count('.') >= 2 and attributes:
                # Try matching with each attribute: type.name.attribute
                for attr in attributes:
                    full_resource_with_attr = f"{resource_type}.{resource_name}.{attr}"
                    if re.search(resource_pattern, full_resource_with_attr, re.IGNORECASE):
                        matched = True
                        break

            if not matched:
                return False

        # Check specific attribute
        if 'attribute' in rule:
            attribute_pattern = rule['attribute']
            # Check if any changed attribute matches
            has_matching_attr = any(
                re.search(attribute_pattern, attr, re.IGNORECASE)
                for attr in attributes
            )
            # Also check diff content for attribute mentions
            has_matching_diff = re.search(attribute_pattern, diff, re.IGNORECASE)

            if not (has_matching_attr or has_matching_diff):
                return False

        # Check operation
        if 'operation' in rule:
            required_op = rule['operation']
            op_value = (operation or "").lower()
            # Support multiple operations: "create|delete"
            if '|' in required_op:
                allowed_ops = [op.strip().lower() for op in required_op.split('|')]
                if op_value not in allowed_ops:
                    return False
            elif op_value != (required_op or "").lower():
                return False

        # All criteria matched
        return True

    def classify_with_rules(self, change: Dict) -> Optional[Tuple[str, Dict]]:
        """
        Classify change using rule-based matching.

        Args:
            change: Change dictionary

        Returns:
            Tuple of (category, rule) if matched, or None
        """
        # Check categories in order: routine → adaptive → transformative → impact
        for category in ['routine', 'adaptive', 'transformative', 'impact']:
            rules = self.rules.get(category, [])

            for rule in rules:
                if self.match_rule(change, rule):
                    return (category.upper(), rule)

        return None

    def classify_with_ai(self, change: Dict) -> Dict:
        """
        Classify change using AI (Claude Haiku).

        Args:
            change: Change dictionary

        Returns:
            Dictionary with category, confidence, reasoning
        """
        if not self.enable_ai or not self.api_key:
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': 'AI fallback not available (no API key or disabled)'
            }

        # Build prompt
        prompt = self._build_ai_prompt(change)

        try:
            # Call Anthropic API
            if HAS_ANTHROPIC_SDK and self.anthropic_client:
                response = self._call_anthropic_sdk(prompt)
            else:
                response = self._call_anthropic_api(prompt)

            # Parse JSON response
            result = json.loads(response)

            # Validate response
            category = result.get('category', 'MANUAL_REVIEW').upper()
            confidence = float(result.get('confidence', 0.0))
            reasoning = result.get('reasoning', 'No reasoning provided')

            # Check confidence threshold
            threshold = self.ai_config.get('confidence_threshold', 0.8)
            if confidence < threshold:
                return {
                    'category': 'MANUAL_REVIEW',
                    'confidence': confidence,
                    'reasoning': f"Low confidence ({confidence:.2f} < {threshold}): {reasoning}"
                }

            return {
                'category': category,
                'confidence': confidence,
                'reasoning': reasoning
            }

        except Exception as e:
            print(f"⚠️  AI classification failed: {e}", file=sys.stderr)
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': f'AI error: {str(e)}'
            }

    def _build_ai_prompt(self, change: Dict) -> str:
        """Build AI classification prompt."""
        resource_type = change.get('type', 'unknown')
        resource_name = change.get('name', 'unnamed')
        operation = change.get('operation', 'unknown')
        attributes = ', '.join(change.get('attributes_changed', []))
        # Allow configurable diff snippet length, defaulting to 1000 characters
        max_diff_chars = self.ai_config.get('max_diff_chars', 1000)
        try:
            max_diff_chars = int(max_diff_chars)
            if max_diff_chars <= 0:
                max_diff_chars = 1000
        except (TypeError, ValueError):
            max_diff_chars = 1000
        diff_snippet = change.get('diff', '')[:max_diff_chars]

        prompt = f"""You are a FedRAMP compliance expert analyzing infrastructure changes.

FedRAMP Change Categories:
- ROUTINE: Regular maintenance, patching, minor capacity changes (no notification required)
- ADAPTIVE: Frequent improvements with minimal security plan changes (10 days after completion)
- TRANSFORMATIVE: Rare, significant changes altering risk profile (30 days initial + 10 days final notice)
- IMPACT: Changes to security boundary or FIPS level (requires new assessment)

Change Details:
- Resource Type: {resource_type}
- Resource Name: {resource_name}
- Operation: {operation}
- Attributes Changed: {attributes}
- Diff Preview:
{diff_snippet}

Classify this change. Respond ONLY with valid JSON in this exact format:
{{
  "category": "ROUTINE|ADAPTIVE|TRANSFORMATIVE|IMPACT",
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation (max 200 chars)"
}}"""

        return prompt

    def _call_anthropic_sdk(self, prompt: str) -> str:
        """Call Anthropic API using SDK."""
        model = self.ai_config.get('model', 'claude-3-haiku-20240307')
        max_tokens = self.ai_config.get('max_tokens', 1024)

        message = self.anthropic_client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return message.content[0].text

    def _call_anthropic_api(self, prompt: str) -> str:
        """Call Anthropic API using requests (fallback)."""
        model = self.ai_config.get('model', 'claude-3-haiku-20240307')
        max_tokens = self.ai_config.get('max_tokens', 1024)

        url = 'https://api.anthropic.com/v1/messages'
        headers = {
            'x-api-key': self.api_key,
            'anthropic-version': '2023-06-01',
            'content-type': 'application/json'
        }
        data = {
            'model': model,
            'max_tokens': max_tokens,
            'messages': [
                {'role': 'user', 'content': prompt}
            ]
        }

        response = requests.post(url, headers=headers, json=data, timeout=30)
        response.raise_for_status()

        result = response.json()
        return result['content'][0]['text']

    def classify_change(self, change: Dict) -> Dict:
        """
        Classify a single change.

        Args:
            change: Change dictionary

        Returns:
            Classification dictionary
        """
        # Try rule-based first
        rule_match = self.classify_with_rules(change)

        if rule_match:
            category, rule = rule_match
            return {
                'category': category,
                'method': 'rule-based',
                'confidence': 1.0,
                'reasoning': rule.get('description', 'Rule matched'),
                'rule_matched': self._format_rule(rule, category)
            }

        # Fallback to AI if enabled
        if self.enable_ai:
            print(f"  🤖 Using AI fallback for {change.get('type')}.{change.get('name')}")
            ai_result = self.classify_with_ai(change)
            return {
                'category': ai_result['category'],
                'method': 'ai-fallback',
                'confidence': ai_result['confidence'],
                'reasoning': ai_result['reasoning'],
                'ai_model': self.ai_config.get('model')
            }

        # No match and no AI
        return {
            'category': 'MANUAL_REVIEW',
            'method': 'unmatched',
            'confidence': 0.0,
            'reasoning': 'No rule matched and AI fallback not enabled'
        }

    def _format_rule(self, rule: Dict, category: str) -> str:
        """Format rule for audit trail."""
        parts = [category.lower()]

        if 'resource' in rule:
            parts.append(rule['resource'])
        if 'pattern' in rule:
            parts.append(f"pattern:{rule['pattern']}")
        if 'attribute' in rule:
            parts.append(f"attr:{rule['attribute']}")

        return '.'.join(parts)

    def classify_all_changes(self, changes_data: Dict) -> Dict:
        """
        Classify all changes in dataset.

        Args:
            changes_data: Changes dictionary from analyzer

        Returns:
            Classifications dictionary
        """
        print(f"🏷️  Classifying changes...")

        classifications = []
        summary = {
            'routine': 0,
            'adaptive': 0,
            'transformative': 0,
            'impact': 0,
            'manual_review': 0
        }

        for file_change in changes_data.get('changes', []):
            file_path = file_change.get('file')
            resources = file_change.get('resources', [])

            for resource in resources:
                classification = self.classify_change(resource)

                # Add file context
                classification['file'] = file_path
                classification['resource'] = f"{resource.get('type')}.{resource.get('name')}"

                classifications.append(classification)

                # Update summary
                category = classification['category'].lower()
                if category in summary:
                    summary[category] += 1
                else:
                    summary['manual_review'] += 1

        # Print summary
        print(f"\n📊 Classification Summary:")
        print(f"  🟢 Routine: {summary['routine']}")
        print(f"  🟡 Adaptive: {summary['adaptive']}")
        print(f"  🟠 Transformative: {summary['transformative']}")
        print(f"  🔴 Impact: {summary['impact']}")
        if summary['manual_review'] > 0:
            print(f"  ⚠️  Manual Review: {summary['manual_review']}")

        return {
            'classifications': classifications,
            'summary': summary,
            'config_version': self.config.get('version', 'default'),
            'ai_enabled': self.enable_ai
        }


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Classify IaC changes for FedRAMP SCN'
    )
    parser.add_argument(
        '--input',
        required=True,
        help='Input JSON file (from analyze_iac_changes.py)'
    )
    parser.add_argument(
        '--output',
        required=True,
        help='Output JSON file for classifications'
    )
    parser.add_argument(
        '--config',
        help='Path to SCN configuration YAML'
    )
    parser.add_argument(
        '--enable-ai',
        action='store_true',
        help='Enable AI fallback for ambiguous cases'
    )

    args = parser.parse_args()

    # Load input changes
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            changes_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Input file not found: {args.input}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in input file: {e}", file=sys.stderr)
        return 1

    # Load config if provided
    config = None
    if args.config:
        classifier = ChangeClassifier()
        config = classifier.load_config_from_file(args.config)

    # Create classifier
    api_key = os.environ.get('ANTHROPIC_API_KEY')
    if args.enable_ai and not api_key:
        print("⚠️  AI fallback enabled but ANTHROPIC_API_KEY not set", file=sys.stderr)

    classifier = ChangeClassifier(config=config, enable_ai=args.enable_ai, api_key=api_key)

    # Classify all changes
    results = classifier.classify_all_changes(changes_data)

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f"\n✅ Classification complete: {output_path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
