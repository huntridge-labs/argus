#!/usr/bin/env python3
"""
FedRAMP SCN Detector - Change Classification Engine

Classifies IaC changes into FedRAMP SCN categories using:
1. Rule-based pattern matching (fast, deterministic)
2. AI fallback with configurable provider (for ambiguous cases, optional)

Categories:
- ROUTINE: No notification required
- ADAPTIVE: Within 10 business days after completion
- TRANSFORMATIVE: 30 days initial + 10 days final + after
- IMPACT: New assessment required
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from .defaults import DEFAULT_RULES, DEFAULT_AI_CONFIG, merge_config, get_default_config


class ChangeClassifier:
    """Classifies IaC changes according to FedRAMP SCN guidelines."""

    def __init__(self, config: Optional[Dict] = None, enable_ai: bool = False, api_key: Optional[str] = None):
        """
        Initialize classifier.

        Args:
            config: Configuration dictionary (or None for defaults)
            enable_ai: Whether to enable AI fallback
            api_key: AI provider API key (or None to resolve from env var)
        """
        # Merge provided config with defaults
        default_config = get_default_config()
        self.config = merge_config(config or {}, default_config)

        self.rules = self.config.get('rules', DEFAULT_RULES)
        self.ai_config = self.config.get('ai_fallback', DEFAULT_AI_CONFIG)
        # AI enablement is controlled exclusively by the --enable-ai CLI flag
        # (or the enable_ai_fallback action input). Config files cannot enable AI.
        self.enable_ai = enable_ai

        # Resolve API key based on configured provider
        from .ai import resolve_api_key
        provider_name = self.ai_config.get('provider', 'anthropic')
        self.api_key = resolve_api_key(provider_name, api_key)

        # Lazily initialize AI classifier only when needed
        self._ai_classifier = None

    def _get_ai_classifier(self):
        """Lazily initialize AI classifier."""
        if self._ai_classifier is None:
            from .ai import AIClassifier
            self._ai_classifier = AIClassifier(
                ai_config=self.ai_config,
                api_key=self.api_key
            )
        return self._ai_classifier

    def load_config_from_file(self, config_path: str) -> Optional[Dict]:
        """Load configuration from YAML file.

        Returns:
            Parsed config dict, empty dict if file not found, or None if YAML/validation is invalid.
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    print(f"Warning: Config file is empty or not a YAML mapping: {config_path}", file=sys.stderr)
                    return {}

                # Validate config structure against schema
                self._validate_config(config)

                print(f"Loaded config from {config_path}")
                return config
        except FileNotFoundError:
            print(f"Warning: Config file not found: {config_path}", file=sys.stderr)
            print("Using default FedRAMP rules", file=sys.stderr)
            return {}
        except yaml.YAMLError as e:
            print(f"Error: Invalid YAML in config file: {e}", file=sys.stderr)
            return None
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return None

    @staticmethod
    def _validate_config(config: Dict) -> None:
        """Validate config structure against the SCN schema."""
        from .config import validate_config_structure
        schema_path = Path(__file__).parent.parent.parent / '.github' / 'actions' / 'scn-detector' / 'schemas' / 'scn-config.schema.json'
        if schema_path.exists():
            with open(schema_path, 'r', encoding='utf-8') as sf:
                schema = json.load(sf)
            validate_config_structure(config, schema)

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

        if not self._match_pattern(rule, resource_type, resource_name, attributes, diff):
            return False
        if not self._match_resource(rule, resource_type, resource_name, attributes):
            return False
        if not self._match_attribute(rule, attributes, diff):
            return False
        if not self._match_operation(rule, operation):
            return False

        return True

    def _match_pattern(self, rule: Dict, resource_type: str, resource_name: str,
                       attributes: List[str], diff: str) -> bool:
        """Check pattern match criterion."""
        if 'pattern' not in rule:
            return True
        match_text = f"{resource_type}.{resource_name} {' '.join(attributes)} {diff}"
        return bool(re.search(rule['pattern'], match_text, re.IGNORECASE))

    def _match_resource(self, rule: Dict, resource_type: str, resource_name: str,
                        attributes: List[str]) -> bool:
        """Check resource type/name match criterion."""
        if 'resource' not in rule:
            return True

        resource_pattern = rule['resource']
        full_resource = f"{resource_type}.{resource_name}"

        matched = re.search(resource_pattern, full_resource, re.IGNORECASE)

        # Try matching with attributes: type.name.attribute
        if not matched and resource_pattern.count('.') >= 2 and attributes:
            for attr in attributes:
                full_resource_with_attr = f"{resource_type}.{resource_name}.{attr}"
                if re.search(resource_pattern, full_resource_with_attr, re.IGNORECASE):
                    return True

        return bool(matched)

    def _match_attribute(self, rule: Dict, attributes: List[str], diff: str) -> bool:
        """Check attribute match criterion."""
        if 'attribute' not in rule:
            return True
        attribute_pattern = rule['attribute']
        has_matching_attr = any(
            re.search(attribute_pattern, attr, re.IGNORECASE)
            for attr in attributes
        )
        has_matching_diff = re.search(attribute_pattern, diff, re.IGNORECASE)
        return bool(has_matching_attr or has_matching_diff)

    def _match_operation(self, rule: Dict, operation: str) -> bool:
        """Check operation match criterion."""
        if 'operation' not in rule:
            return True
        required_op = rule['operation']
        op_value = (operation or "").lower()
        if '|' in required_op:
            allowed_ops = [op.strip().lower() for op in required_op.split('|')]
            return op_value in allowed_ops
        return op_value == (required_op or "").lower()

    def classify_with_rules(self, change: Dict) -> Optional[Tuple[str, Dict]]:
        """Classify change using rule-based matching."""
        for category in ['routine', 'adaptive', 'transformative', 'impact']:
            for rule in self.rules.get(category, []):
                if self.match_rule(change, rule):
                    return (category.upper(), rule)
        return None

    def classify_with_ai(self, change: Dict) -> Dict:
        """Classify change using AI (Claude Haiku)."""
        if not self.enable_ai or not self.api_key:
            return {
                'category': 'MANUAL_REVIEW',
                'confidence': 0.0,
                'reasoning': 'AI fallback not available (no API key or disabled)'
            }
        return self._get_ai_classifier().classify(change)

    def classify_change(self, change: Dict) -> Dict:
        """Classify a single change (rules first, AI fallback)."""
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

        if self.enable_ai:
            print(f"  Using AI fallback for {change.get('type')}.{change.get('name')}")
            ai_result = self.classify_with_ai(change)
            return {
                'category': ai_result['category'],
                'method': 'ai-fallback',
                'confidence': ai_result['confidence'],
                'reasoning': ai_result['reasoning'],
                'ai_model': self.ai_config.get('model')
            }

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
        """Classify all changes in dataset."""
        print("Classifying changes...")

        classifications = []
        summary = {
            'routine': 0, 'adaptive': 0,
            'transformative': 0, 'impact': 0,
            'manual_review': 0
        }

        for file_change in changes_data.get('changes', []):
            file_path = file_change.get('file')
            for resource in file_change.get('resources', []):
                classification = self.classify_change(resource)
                classification['file'] = file_path
                classification['resource'] = f"{resource.get('type')}.{resource.get('name')}"
                classifications.append(classification)

                category = classification['category'].lower()
                if category in summary:
                    summary[category] += 1
                else:
                    summary['manual_review'] += 1

        print(f"\nClassification Summary:")
        print(f"  Routine: {summary['routine']}")
        print(f"  Adaptive: {summary['adaptive']}")
        print(f"  Transformative: {summary['transformative']}")
        print(f"  Impact: {summary['impact']}")
        if summary['manual_review'] > 0:
            print(f"  Manual Review: {summary['manual_review']}")

        return {
            'classifications': classifications,
            'summary': summary,
            'config_version': self.config.get('version', 'default'),
            'ai_enabled': self.enable_ai
        }
