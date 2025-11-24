from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

# Specification V2.1.0


def is_detection_rule(rule: SigmaRule | SigmaCorrelationRule) -> bool:
    return True if isinstance(rule, SigmaRule) else False


def is_correlation_rule(rule: SigmaRule | SigmaCorrelationRule) -> bool:
    return True if isinstance(rule, SigmaCorrelationRule) else False
