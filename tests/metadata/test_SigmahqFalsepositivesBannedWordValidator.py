from wsgiref.validate import validator

import pytest
from datetime import datetime

from sigma.rule import SigmaRule
from sigma.validators.sigmahq.metadata import (
    SigmahqFalsepositivesBannedWordIssue,
    SigmahqFalsepositivesBannedWordValidator,
    SigmahqFalsepositivesTypoWordIssue,
    SigmahqFalsepositivesTypoWordValidator,
    SigmahqLinkInDescriptionIssue,
    SigmahqLinkInDescriptionValidator,
    SigmahqUnknownFieldIssue,
    SigmahqUnknownFieldValidator,
    SigmahqRedundantModifiedIssue,
    SigmahqRedundantModifiedValidator,
    SigmahqStatusToHighIssue,
    SigmahqStatusToHighValidator,
    SigmahqGithubLinkIssue,
    SigmahqGithubLinkValidator,
    SigmahqMitreLinkIssue,
    SigmahqMitreLinkValidator,
)


def test_validator_SigmahqFalsepositivesBannedWord():
    validator = SigmahqFalsepositivesBannedWordValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Pentest tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Pentest")]


def test_validator_SigmahqFalsepositivesBannedWord_custom():
    validator = SigmahqFalsepositivesBannedWordValidator(word_list=("maybe",))
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Maybe
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesBannedWordIssue([rule], "Maybe")]


def test_validator_SigmahqFalsepositivesBannedWord_valid():
    validator = SigmahqFalsepositivesBannedWordValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - GPO tools
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqFalsepositivesTypoWord():
    validator = SigmahqFalsepositivesTypoWordValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - legitimeate AD tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesTypoWordIssue([rule], "legitimeate")]


def test_validator_SigmahqFalsepositivesTypoWord_custom():
    validator = SigmahqFalsepositivesTypoWordValidator(word_list=("unkwon",))
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - Unkwon AD tools
    """
    )
    assert validator.validate(rule) == [SigmahqFalsepositivesTypoWordIssue([rule], "Unkwon")]


def test_validator_SigmahqFalsepositivesTypoWord_valid():
    validator = SigmahqFalsepositivesTypoWordValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: ATT&CK rule
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    falsepositives:
        - legitimate AD tools
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqLinkDescription_https():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: rule from https://somewhereundertheraimbow
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue([rule], "https://")]


def test_validator_SigmahqLinkDescription_ftp():
    validator = SigmahqLinkInDescriptionValidator(word_list=("http://", "https://", "ftp:"))
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: pdf found here ftp://somewhereundertheraimbow
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqLinkInDescriptionIssue([rule], "ftp:")]


def test_validator_SigmahqLinkDescription_valid():
    validator = SigmahqLinkInDescriptionValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: rule from https://somewhereundertheraimbow
    references:
        - https://somewhereundertheraimbow
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


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


def test_validator_SigmahqRedundantModified():
    validator = SigmahqRedundantModifiedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    date: 2024-08-09
    modified: 2024-08-09
    logsource:
        category: test
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqRedundantModifiedIssue([rule])]


def test_validator_SigmahqRedundantModified_valid():
    validator = SigmahqRedundantModifiedValidator()
    rule = SigmaRule.from_yaml(
        """
    title: Test
    description: Test
    logsource:
        category: test
    date: 2024-08-09
    modified: 2025-05-30
    detection:
        sel:
            field: value
        condition: sel
    """
    )
    assert validator.validate(rule) == []


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
