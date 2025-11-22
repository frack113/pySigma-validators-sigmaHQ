from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

from sigma.validators.sigmahq.field import (
    SigmahqSpaceFieldNameIssue,
    SigmahqSpaceFieldNameValidator,
)


def test_validator_sigmahq_space_fieldname_with_space():
    """Test that space in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "space name")]


def test_validator_sigmahq_space_fieldname_with_underscore():
    """Test that underscore in field names are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: A Space Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space_name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_sigmahq_space_fieldname_duplicate_case_insensitive():
    """Test that duplicate case insensitive field names with spaces are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command Line: 'invalid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "Command Line")]


def test_validator_sigmahq_space_fieldname_duplicate_case_insensitive_valid():
    """Test that duplicate case insensitive field names with underscores are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            Command_Line: 'valid'
            CommandLine: 'valid'
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_sigmahq_space_fieldname_multiple_spaces():
    """Test that multiple spaces in field names are detected"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Multiple Spaces Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
            space  name: 'error'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqSpaceFieldNameIssue([rule], "space  name")]


def test_validator_sigmahq_space_fieldname_no_spaces():
    """Test that field names without spaces are valid"""
    validator = SigmahqSpaceFieldNameValidator()
    rule = SigmaRule.from_yaml(
        """
    title: No Spaces Field Name
    status: test
    logsource:
        category: test
    detection:
        sel:
            field_name: 'value'
            another_field: 'another_value'
        condition: sel
    """
    )
    assert validator.validate(rule) == []
