from sigma.rule import SigmaRule
from sigma.validators.sigmahq.detection import (
    SigmahqCategoryEventIdIssue,
    SigmahqCategoryEventIdValidator,
)
from sigma.correlations import SigmaCorrelationRule
import pytest


def test_validator_sigmahq_category_eventid_invalid_eventid_with_category_that_does_not_require_it():
    """Test when EventID is used with a windows category that doesn't require it"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        sel:
            field: path\\*something
            EventID: 4103
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqCategoryEventIdIssue([rule])]


def test_validator_sigmahq_category_eventid_valid_no_eventid_with_category_that_does_not_require_it():
    """Test when no EventID is used with a windows category that doesn't require it"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_sigmahq_category_eventid_other_product():
    """Test when product is not windows - should not trigger validation"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: linux
        category: process_creation
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_sigmahq_category_eventid_invalid_eventid_with_process_creation_category():
    """Test when EventID is used with process_creation category that doesn't require it"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            EventID: 1234
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqCategoryEventIdIssue([rule])]


def test_validator_sigmahq_category_eventid_valid_no_eventid_with_process_creation_category():
    """Test when no EventID is used for process_creation category that doesn't require it"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_sigmahq_category_eventid_multiple_fields_with_eventid():
    """Test when EventID is used alongside other fields with a category that doesn't require it"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: ps_module
    detection:
        sel:
            field1: value1
            EventID: 4103
            field2: value2
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqCategoryEventIdIssue([rule])]


def test_validator_sigmahq_category_eventid_category_not_in_config():
    """Test when category is not in the windows_no_eventid config"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: some_unknown_category
    detection:
        sel:
            EventID: 1234
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_sigmahq_category_eventid_correlation_rule():
    """Test that correlation rules are not validated"""
    validator = SigmahqCategoryEventIdValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
    title: Test Correlation
    id: 0e95725d-7320-415d-80f7-004da920fc11
    correlation:
        type: temporal
        rules:
            - recon_cmd_a
            - recon_cmd_b
        timespan: 5m
        group-by:
            - ComputerName
    """
    )
    assert validator.validate(rule) == []
