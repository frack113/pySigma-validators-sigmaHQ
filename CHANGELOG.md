# CHANGELOG

## 2026-10-24 - v0.22.0

- Migrate to pySigma 2.x: `pysigma >=2.0,<3.0` (SigmaPolicy, RE2 default regex engine)
- Drop Python 3.10 support; require `>=3.11,<4.0` (matches pySigma 2.x)
- Test the unsupported-regex-group-construct validator with `TrustedPolicy`
  (Python regex engine) so lookahead/lookbehind rules stay parseable

## 2026-08-21 - v0.21.1

- Harden data loading: warn on http:// URLs, validate local file paths
- Remove mutable state from detection item validators
- Performance: single-pass technique/tactic check, hoisted constants
- Lint: replace magic-value noqas with named constants

## 2024-08-09

- Update taxonomy
- Use json for data instead of config.py
- Use diskcache for caching remote data
- Fix invalid sigma syntax
- Move field validators to validator files
