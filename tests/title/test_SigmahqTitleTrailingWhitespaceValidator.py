# tests/title/test_SigmahqTitleCaseValidator.py
from sigma.validators.sigmahq.title import (
    SigmahqTitleTrailingWhitespaceValidator,
    SigmahqTitleTrailingWhitespaceIssue,
)
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


def test_valid_title_no_whitespace_sigma_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_rule("Valid title example")
    assert len(validator.validate(rule)) == 0


def test_trailing_whitespace_sigma_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_rule("Title with trailing space ")
    assert validator.validate(rule) == [SigmahqTitleTrailingWhitespaceIssue([rule])]


def test_leading_whitespace_sigma_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_rule(" Leading title")
    assert validator.validate(rule) == [SigmahqTitleTrailingWhitespaceIssue([rule])]


def test_leading_and_trailing_whitespace_sigma_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_rule("  Surrounded by spaces  ")
    assert validator.validate(rule) == [SigmahqTitleTrailingWhitespaceIssue([rule])]


def test_internal_multiple_spaces_sigma_rule_not_flagged():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_rule("Title  with  internal  spaces")
    assert len(validator.validate(rule)) == 0


def test_trailing_tab_and_newline_sigma_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    # include a literal tab and newline at the end
    rule = create_sigma_rule("Title with tab\t")
    assert validator.validate(rule) == [SigmahqTitleTrailingWhitespaceIssue([rule])]


def test_empty_and_whitespace_only_sigma_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule_empty = create_sigma_rule("")
    rule_spaces = create_sigma_rule("   ")
    assert len(validator.validate(rule_empty)) == 0
    assert len(validator.validate(rule_spaces)) == 0


def test_valid_title_no_whitespace_sigma_correlation_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_correlation_rule("Valid correlation title")
    assert len(validator.validate(rule)) == 0


def test_trailing_whitespace_sigma_correlation_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_correlation_rule("Correlation trailing ")
    assert validator.validate(rule) == [SigmahqTitleTrailingWhitespaceIssue([rule])]


def test_leading_whitespace_sigma_correlation_rule():
    validator = SigmahqTitleTrailingWhitespaceValidator()
    rule = create_sigma_correlation_rule(" Leading correlation")
    assert validator.validate(rule) == [SigmahqTitleTrailingWhitespaceIssue([rule])]
