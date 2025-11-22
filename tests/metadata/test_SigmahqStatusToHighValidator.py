from wsgiref.validate import validator

import pytest
from datetime import datetime

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqStatusToHighIssue,
    SigmahqStatusToHighValidator,
    SigmahqGithubLinkIssue,
    SigmahqGithubLinkValidator,
    SigmahqMitreLinkIssue,
    SigmahqMitreLinkValidator,
)


def test_validator_SigmahqStatusToHigh():
    validator = SigmahqStatusToHighValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    rule.date = datetime.now().date()
    assert validator.validate(rule) == [SigmahqStatusToHighIssue([rule])]


def test_validator_SigmahqStatusToHigh_valid():
    validator = SigmahqStatusToHighValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqStatusToHigh_with_regression_valid():
    validator = SigmahqStatusToHighValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: test
    date: 1975-01-01
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    regression_tests_path: regression/rule/test_rule.yml
    """
    )
    rule.date = datetime.now().date()
    assert validator.validate(rule) == []


def test_validator_SigmahqGithubLink():
    validator = SigmahqGithubLinkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/README.md
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == [
        SigmahqGithubLinkIssue(
            [rule], "https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/main/README.md"
        )
    ]


def test_validator_SigmahqGithubLink_valid():
    validator = SigmahqGithubLinkValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    status: stable
    references:
        - https://github.com/SigmaHQ/pySigma-validators-sigmaHQ/blob/e557b4acd15b24ad5e7923c69a3e73c7a512ed2c/README.md
    logsource:
        category: test
    detection:
        sel:
            candle|exists: true
        condition: sel
    """
    )
    assert validator.validate(rule) == []


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
