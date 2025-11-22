from sigma.validators.sigmahq.title import SigmahqTitleLengthValidator
from sigma.correlations import SigmaCorrelationRule


def test_SigmahqTitleLength_valid_sigma_correlation_rule():
    """
    Tests that a valid title length rule passes the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: A valid title length
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
    assert validator.validate(rule) == []


def test_SigmahqTitleLength_invalid_sigma_correlation_rule():
    """
    Tests that an invalid title length rule fails the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        f"""
title: {'A' * 121}
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
    assert len(validator.validate(rule)) > 0


def test_SigmahqTitleLength_empty_title():
    """
    Tests that a rule with an empty title fails the validator.
    """
    validator = SigmahqTitleLengthValidator()
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
    assert len(validator.validate(rule)) > 0


def test_SigmahqTitleLength_single_character_title():
    """
    Tests that a rule with a single character title passes the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: A
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
    assert validator.validate(rule) == []


def test_SigmahqTitleLength_max_length_title():
    """
    Tests that a rule with a title at the maximum allowed length passes the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        f"""
title: {'A' * 120}  # max length is 120 characters
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
    assert validator.validate(rule) == []


def test_SigmahqTitleLength_exceeding_max_length_title():
    """
    Tests that a rule with a title exceeding the maximum allowed length fails the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        f"""
title: {'A' * 121}  # exceeding max length of 120 characters
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
    assert len(validator.validate(rule)) > 0


def test_SigmahqTitleLength_whitespace_title():
    """
    Tests that a rule with a title containing only whitespace fails the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: "    \t   \n   "
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
    assert len(validator.validate(rule)) > 0


def test_SigmahqTitleLength_unicode_title():
    """
    Tests that a rule with a title containing Unicode characters passes the validator.
    """
    validator = SigmahqTitleLengthValidator()
    rule = SigmaCorrelationRule.from_yaml(
        """
title: A valid title with unicode 😊
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
    assert validator.validate(rule) == []
