from dataclasses import dataclass
from typing import List, Tuple, ClassVar, Optional
from sigma.rule import SigmaRule
from sigma.correlations import SigmaCorrelationRule
from sigma.validators.base import (
    SigmaRuleValidator,
    SigmaValidationIssue,
    SigmaValidationIssueSeverity,
)
from .config import ConfigHQ

config = ConfigHQ()


def _extract_title(rule) -> Optional[str]:
    """Return the title string for supported rule objects, or None.

    This helper centralizes the logic of extracting a title so validators
    don't repeat isinstance/getattr checks.
    """
    if isinstance(rule, (SigmaRule, SigmaCorrelationRule)):
        title = getattr(rule, "title", None)
        return title if isinstance(title, str) else None
    return None


@dataclass
class SigmahqTitleLengthIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that is too long."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


@dataclass(frozen=True)
class SigmahqTitleLengthValidator(SigmaRuleValidator):
    """Checks if a rule has an excessively long title.

    Empty or whitespace-only titles are considered invalid by this validator.
    """

    max_length: int = 120

    def validate(self, rule) -> List[SigmaValidationIssue]:
        title = _extract_title(rule)
        if title is None:
            return []

        if title.strip() == "":
            return [SigmahqTitleLengthIssue([rule])]

        if len(title) > self.max_length:
            return [SigmahqTitleLengthIssue([rule])]
        return []


@dataclass
class SigmahqTitleStartIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that starts with the word 'Detect' or 'Detects'."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqTitleStartValidator(SigmaRuleValidator):
    """Checks if a rule title starts with the word 'Detect' or 'Detects'.

    This check does not strip leading whitespace on purpose: the title's
    exact beginning is what matters here.
    """

    def validate(self, rule) -> List[SigmaValidationIssue]:
        title = _extract_title(rule)
        if not title or title.strip() == "":
            return []

        if title.startswith(("Detect ", "Detects ")):
            return [SigmahqTitleStartIssue([rule])]
        return []


@dataclass
class SigmahqTitleDotEndIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title that ends with a dot (.)"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqTitleDotEndValidator(SigmaRuleValidator):
    """Checks if a rule has a title that ends with a dot ('.')."""

    def validate(self, rule) -> List[SigmaValidationIssue]:
        title = _extract_title(rule)
        if not title or title.strip() == "":
            return []

        if title.endswith("."):
            return [SigmahqTitleDotEndIssue([rule])]
        return []


@dataclass
class SigmahqTitleTrailingWhitespaceIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule title contains leading or trailing whitespace."
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM


class SigmahqTitleTrailingWhitespaceValidator(SigmaRuleValidator):
    """Checks whether a rule's title has leading or trailing whitespace.

    Titles that are empty or whitespace-only are not flagged here; other
    validators handle those cases.
    """

    def validate(self, rule) -> List[SigmaValidationIssue]:
        title = _extract_title(rule)
        if not title or title.strip() == "":
            return []

        if title != title.strip():
            return [SigmahqTitleTrailingWhitespaceIssue([rule])]
        return []


@dataclass
class SigmahqTitleCaseIssue(SigmaValidationIssue):
    description: ClassVar[str] = "Rule has a title with invalid casing"
    severity: ClassVar[SigmaValidationIssueSeverity] = SigmaValidationIssueSeverity.MEDIUM
    word: str


@dataclass(frozen=True)
class SigmahqTitleCaseValidator(SigmaRuleValidator):
    """Checks if a rule has a title with invalid casing."""

    word_list: Tuple[str, ...] = (
        "a",
        "an",
        "and",
        "as",
        "at",
        "by",
        "for",
        "from",
        "in",
        "new",
        "of",
        "on",
        "or",
        "over",
        "the",
        "through",
        "to",
        "via",
        "with",
        "without",
    )

    def validate(self, rule) -> List[SigmaValidationIssue]:
        title = _extract_title(rule)
        if not title or not title.strip():
            return []

        for word in title.split():
            if (
                word.islower()
                and word.lower() not in self.word_list
                and "." not in word
                and "/" not in word
                and "_" not in word
                and not word[0].isdigit()
            ):
                return [SigmahqTitleCaseIssue([rule], word)]
        return []
