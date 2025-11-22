from wsgiref.validate import validator

import pytest
from datetime import datetime

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqUnknownFieldIssue,
    SigmahqUnknownFieldValidator,
)


def test_validator_SigmahqUnknownField():
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    created: 2024-08-09
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqUnknownFieldIssue([rule], ["created"])]


def test_validator_SigmahqUnknownField_valid():
    validator = SigmahqUnknownFieldValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    date: 2024-08-09
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []
