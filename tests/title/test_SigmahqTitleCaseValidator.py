# tests/title/test_SigmahqTitleCaseValidator.py
from sigma.validators.sigmahq.title import SigmahqTitleCaseValidator, SigmahqTitleCaseIssue
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule


def create_sigma_rule(title):
    yaml_text = f"""title: "{title}"
id: "12345678-1234-5678-1234-567812345678"
status: "experimental"
description: "A test rule."
references:
    - "https://example.com"
logsource:
    category: "process_creation"
    product: "windows"
detection:
    selection:
        EventID: 1
    condition: selection
"""
    return SigmaRule.from_yaml(yaml_text)


def create_sigma_correlation_rule(title):
    yaml_text = f"""title: "{title}"
id: "12345678-1234-5678-1234-567812345679"
status: "experimental"
description: "A test correlation rule."
references:
    - "https://example.com"
correlation:
    type: event_count
    rules:
        - rule_id_1
        - rule_id_2
    timespan: "1h"
    group-by:
        - ComputerName
    condition:
        gte: 100
"""
    return SigmaCorrelationRule.from_yaml(yaml_text)


def test_valid_title():
    sigma_rule = create_sigma_rule("Valid Title Case")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_rule))
    assert not issues


def test_invalid_title():
    sigma_rule = create_sigma_rule("invalid title case")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_rule))
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqTitleCaseIssue)


def test_valid_correlation_title():
    sigma_correlation_rule = create_sigma_correlation_rule("Valid Title Case")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_correlation_rule))
    assert not issues


def test_invalid_correlation_title():
    sigma_correlation_rule = create_sigma_correlation_rule("invalid title case")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_correlation_rule))
    assert len(issues) == 1
    assert isinstance(issues[0], SigmahqTitleCaseIssue)


def test_title_with_numbers():
    sigma_rule = create_sigma_rule("Valid Title Case with Numbers 123")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_rule))
    assert not issues


def test_title_with_special_characters():
    sigma_rule = create_sigma_rule("Valid Title Case with Special Characters !@#")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_rule))
    assert not issues


def test_title_with_punctuation():
    sigma_rule = create_sigma_rule("Valid Title, Case. With: Punctuation?")
    validator = SigmahqTitleCaseValidator()
    issues = list(validator.validate(sigma_rule))
    assert not issues
