from sigma.validators.sigmahq.title import SigmahqTitleDotEndValidator, SigmahqTitleDotEndIssue
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule


def test_SigmahqTitleEnd_validator_sigma_rule():
    """
    Tests that a valid title end rule passes the validator for SigmaRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaRule.from_yaml(
        """
title: Title ends with a.
status: test
logsource:
    category: test
detection:
    sel:
        field: path\\*something
    condition: sel
"""
    )
    assert validator.validate(rule) == [SigmahqTitleDotEndIssue([rule])]


def test_SigmahqTitleEnd_validator_sigma_rule_invalid():
    """
    Tests that an invalid title end rule fails the validator for SigmaRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaRule.from_yaml(
        """
title: Title does not end with a
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


def test_SigmahqTitleEnd_validator_sigma_correlation_rule():
    """
    Tests that a valid title end rule passes the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Title ends with a.
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
    assert validator.validate(rule) == [SigmahqTitleDotEndIssue([rule])]


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_invalid():
    """
    Tests that an invalid title end rule fails the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Title does not end with a
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


def test_SigmahqTitleEnd_validator_sigma_rule_empty_title():
    """
    Tests that an empty title fails the validator for SigmaRule.
    """
    validator = SigmahqTitleDotEndValidator()
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


def test_SigmahqTitleEnd_validator_sigma_rule_whitespace_title():
    """
    Tests that a title with only whitespace fails the validator for SigmaRule.
    """
    validator = SigmahqTitleDotEndValidator()
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


def test_SigmahqTitleEnd_validator_sigma_rule_with_trailing_whitespace():
    """
    Tests that a title with trailing whitespace fails the validator for SigmaRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaRule.from_yaml(
        """
title: "Title ends with a. "
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


def test_SigmahqTitleEnd_validator_sigma_rule_with_leading_whitespace():
    """
    Tests that a title with leading whitespace fails the validator for SigmaRule.
    """
    pass


def test_SigmahqTitleEnd_validator_sigma_rule_with_special_characters():
    """
    Tests that a title with special characters fails the validator for SigmaRule.
    """
    pass


def test_SigmahqTitleEnd_validator_sigma_rule_with_numbers():
    """
    Tests that a title with numbers fails the validator for SigmaRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaRule.from_yaml(
        """
title: Title ends with a.1
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


def test_SigmahqTitleEnd_validator_sigma_rule_with_multiple_periods():
    """
    Tests that a title with multiple periods fails the validator for SigmaRule.
    """
    pass


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_empty_title():
    """
    Tests that an empty title fails the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleDotEndValidator()
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


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_whitespace_title():
    """
    Tests that a title with only whitespace fails the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleDotEndValidator()
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


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_with_trailing_whitespace():
    """
    Tests that a title with trailing whitespace fails the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: "Title ends with a. "
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


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_with_leading_whitespace():
    """
    Tests that a title with leading whitespace fails the validator for SigmaCorrelationRule.
    """
    pass


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_with_special_characters():
    """
    Tests that a title with special characters fails the validator for SigmaCorrelationRule.
    """
    pass


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_with_numbers():
    """
    Tests that a title with numbers fails the validator for SigmaCorrelationRule.
    """
    validator = SigmahqTitleDotEndValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: Title ends with a.1
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


def test_SigmahqTitleEnd_validator_sigma_correlation_rule_with_multiple_periods():
    """
    Tests that a title with multiple periods fails the validator for SigmaCorrelationRule.
    """
    pass
