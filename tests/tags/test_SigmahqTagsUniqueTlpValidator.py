# tests/test_tags.py

from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection

from sigma.validators.sigmahq.tags import (
    SigmahqTagsUniqueTlpIssue,
    SigmahqTagsUniqueTlpValidator,
)


def test_validator_SigmahqTagsUniqueTlp():
    validator = SigmahqTagsUniqueTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.clear
        - tlp.amber
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == [SigmahqTagsUniqueTlpIssue([rule])]


def test_validator_SigmahqTagsUniqueTlp_valid():
    validator = SigmahqTagsUniqueTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - tlp.amber
        - attack.t1234
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []


def test_validator_SigmahqTagsNoTlp():
    # Test for no TLP tags
    validator = SigmahqTagsUniqueTlpValidator()
    rule = SigmaRule.from_yaml(
        """
    title: test
    status: unsupported
    tags:
        - detection.dfir
    logsource:
        category: test
    detection:
        sel:
            field: path\\*something
        condition: sel
    """
    )
    assert validator.validate(rule) == []
