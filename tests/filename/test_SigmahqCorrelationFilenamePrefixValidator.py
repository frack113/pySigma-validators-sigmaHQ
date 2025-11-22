from wsgiref.validate import validator

import pytest
from sigma.rule import SigmaRule, SigmaLogSource
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

from sigma.validators.sigmahq.filename import (
    SigmahqCorrelationFilenamePrefixIssue,
    SigmahqCorrelationFilenamePrefixValidator,
)


def test_validator_SigmahqCorrelationFilename():
    """Test that correlation pytest_files without correlation_ prefix fail validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/pytest_files/rules-correlations/invalid_prefix_name.yml"]
    )
    rule = sigma_collection[0]
    assert isinstance(rule, SigmaCorrelationRule)
    assert validator.validate(rule) == [
        SigmahqCorrelationFilenamePrefixIssue([rule], "invalid_prefix_name.yml")
    ]


def test_validator_SigmahqCorrelationFilename_valid():
    """Test that correlation pytest_files with correlation_ prefix pass validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/pytest_files/rules-correlations/correlation_valid_filename.yml"]
    )
    rule = sigma_collection[0]
    assert isinstance(rule, SigmaCorrelationRule)
    assert validator.validate(rule) == []


def test_validator_SigmahqCorrelationFilename_combined_valid():
    """Test that combined format pytest_files with correlation_ prefix pass validation"""
    validator = SigmahqCorrelationFilenamePrefixValidator()
    sigma_collection = SigmaCollection.load_ruleset(
        ["tests/pytest_files/rules-correlations/correlation_combined_format.yml"]
    )

    # Find the correlation rule in the combined file
    correlation_rule = None
    for rule in sigma_collection.rules:
        if isinstance(rule, SigmaCorrelationRule):
            correlation_rule = rule
            break

    assert correlation_rule is not None
    assert validator.validate(correlation_rule) == []
