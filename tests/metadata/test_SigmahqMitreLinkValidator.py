from wsgiref.validate import validator

import pytest
from datetime import datetime

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqMitreLinkIssue,
    SigmahqMitreLinkValidator,
)


def test_validator_SigmahqMitreLink():
    validator = SigmahqMitreLinkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://attack.mitre.org/techniques/T1588/007/
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqMitreLinkIssue([rule], "https://attack.mitre.org/techniques/T1588/007/")
    ]


def test_validator_SigmahqMitreLink_valid():
    validator = SigmahqMitreLinkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - http://some-blog.org
    tag:
        - attack.t1588.007
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == []
