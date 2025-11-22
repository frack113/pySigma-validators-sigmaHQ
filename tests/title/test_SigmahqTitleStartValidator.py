# tests/title/test_SigmahqTitleStartValidator.py
from sigma.validators.sigmahq.title import SigmahqTitleStartValidator, SigmahqTitleStartIssue
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule


def test_SigmahqTitleStart_validator_sigma_correlation_rule():
    """
    Tests that a valid title start rule passes the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleStartValidator()
    # Create a proper correlation rule with correct structure using from_yaml
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Detect something
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(rule) == [SigmahqTitleStartIssue([rule])]


def test_SigmahqTitleStart_validator_sigma_correlation_rule_invalid():
    """
    Tests that an invalid title start rule fails the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleStartValidator()
    # Create a proper correlation rule with incorrect title
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Title does not start with a specific character
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_rule():
    """
    Tests that a valid title start rule passes the validator for SigmaRule.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: Detect something
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleStartIssue([rule])]


def test_SigmahqTitleStart_validator_sigma_rule_invalid():
    """
    Tests that an invalid title start rule fails the validator for SigmaRule.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: Title does not start with a specific character
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_correlation_rule_edge_case():
    """
    Tests edge case where title starts with a different variation of 'Detect'.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Detects something
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert validator.validate(rule) == [SigmahqTitleStartIssue([rule])]


def test_SigmahqTitleStart_validator_sigma_correlation_rule_no_match():
    """
    Tests case where title does not start with 'Detect' or 'Detects'.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Something else
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_rule_no_match():
    """
    Tests case where title does not start with 'Detect' or 'Detects'.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: Something else
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_correlation_rule_empty_title():
    """
    Tests case where the title is empty.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: ""
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_rule_empty_title():
    """
    Tests case where the title is empty.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: ""
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_correlation_rule_whitespace_title():
    """
    Tests case where the title is only whitespace.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: "   "
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_rule_whitespace_title():
    """
    Tests case where the title is only whitespace.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: "   "
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_correlation_rule_title_with_numbers():
    """
    Tests case where the title starts with numbers.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: 123 Detect something
status: test
correlation:
    type: event_count
    rules:
        - rule1
    timespan: 1h
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    )
    assert len(validator.validate(rule)) == 0


def test_SigmahqTitleStart_validator_sigma_rule_title_with_special_chars():
    """
    Tests case where the title starts with special characters.
    """
    validator = SigmahqTitleStartValidator()
    rule = SigmaRule.from_yaml(
        """
title: Detect! something
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert len(validator.validate(rule)) == 0
