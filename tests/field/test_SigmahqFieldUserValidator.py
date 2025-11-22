from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule
from sigma.types import SigmaRegularExpression

from sigma.validators.sigmahq.field import (
    SigmahqFieldUserIssue,
    SigmahqFieldUserValidator,
)


def test_validator_SigmahqFieldUserValidator():
    """Test that localized user names are detected"""
    validator = SigmahqFieldUserValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Duplicate Case InSensitive
    status: test
    logsource:
        category: process_creation
        product: windows
    detection:
        sel:
            UserName: 'AUTORITE NT'
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqFieldUserIssue([rule], "UserName", "AUTORITE NT")]
