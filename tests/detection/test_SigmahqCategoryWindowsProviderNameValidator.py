# tests/detection/test_SigmahqCategoryWindowsProviderNameValidator.py
import pytest
from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqCategoryWindowsProviderNameIssue,
    SigmahqCategoryWindowsProviderNameValidator,
)


def test_validator_SigmahqCategoryWindowsProviderName__provider():
    validator = SigmahqCategoryWindowsProviderNameValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqCategoryWindowsProviderName_valid_provider():
    """Test that valid provider names are accepted for process_creation category"""
    validator = SigmahqCategoryWindowsProviderNameValidator()
    rule = SigmaRule.from_yaml(
        """
title: Test Rule
status: test
logsource:
    product: windows
    category: image_load
detection:
    sel:
        field: path\\*something
        Provider_Name: Microsoft-Windows-Sysmon
    condition: sel
"""
    )
    # This should return no issues since Security-Auditing is valid for process_creation
    assert validator.validate(rule) == [SigmahqCategoryWindowsProviderNameIssue([rule])]
