from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule

from sigma.validators.sigmahq.detection import (
    SigmahqUnsupportedRegexGroupConstructIssue,
    SigmahqUnsupportedRegexGroupConstructValidator,
)


def test_validator_SigmahqUnsupportedRegexGroupConstruct():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'A(?=B)'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_valid():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'a\\w+b'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqUnsupportedRegexGroupConstruct_lookbehind():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'A(?<!B)'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?<!B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_negative_lookahead():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'A(?!B)'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?!B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_positive_lookbehind():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'A(?<=B)'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "A(?<=B)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_complex_regex():
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: '(?P<name>\\w+)(?=\\s+\\w+)'
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqUnsupportedRegexGroupConstructIssue([rule], "(?P<name>\\w+)(?=\\s+\\w+)")
    ]


def test_validator_SigmahqUnsupportedRegexGroupConstruct_no_re_modifier():
    """Test that non-regex modifiers don't trigger validation"""
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field: value  # Not using re modifier
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqUnsupportedRegexGroupConstruct_empty_value():
    """Test with empty regex value"""
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: ''
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqUnsupportedRegexGroupConstruct_multiple_issues():
    """Test multiple unsupported regex constructs"""
    validator = SigmahqUnsupportedRegexGroupConstructValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel1:
            field|re: 'A(?=B)'
        sel2:
            field|re: 'C(?!D)'
        condition: sel1 or sel2
    """
    )
    result = validator.validate(rule)
    # Should have two issues - one for each regex construct
    assert len(result) == 2
    assert any("A(?=B)" in str(issue) for issue in result)
    assert any("C(?!D)" in str(issue) for issue in result)


def test_validator_SigmahqUnsupportedRegexGroupConstruct_with_different_modifiers():
    """Test regex validation with various modifiers"""
    validator = SigmahqUnsupportedRegexGroupConstructValidator()

    # Test that valid re modifier doesn't trigger issues
    rule1 = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'test.*pattern'
        condition: sel
    """
    )

    # This should NOT trigger any issues since it's a valid regex without unsupported constructs
    assert validator.validate(rule1) == []

    # Test that invalid modifier does trigger an issue
    rule2 = SigmaRule.from_yaml(
        """
    title: Test Rule
    status: test
    logsource:
        product: windows
        category: process_creation
    detection:
        sel:
            field|re: 'test(?=pattern)'
        condition: sel
    """
    )

    result = validator.validate(rule2)
    assert len(result) == 1
    assert "test(?=pattern)" in str(result[0])
