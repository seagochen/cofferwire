# Contributing to Cofferwire

Cofferwire welcomes specification reviews, interoperability work, test vectors, implementation changes and threat-model analysis.

## Before contributing

- discuss substantial wire-format or cryptographic changes in an issue first;
- keep application-specific behavior out of the core protocol;
- do not introduce new cryptographic constructions without a standards-based rationale;
- add or update conformance tests for every normative behavior change;
- preserve interoperability unless the change follows the documented versioning process.

## Specification changes

A normative change should include:

1. the problem and threat or use case;
2. proposed normative text;
3. compatibility and downgrade impact;
4. positive and negative vectors;
5. conformance-test changes;
6. privacy and operational tradeoffs.

Typos and non-normative clarifications may use a normal pull request. The full RFC/change-control process will be defined during milestone M0.

## Code changes

Rust code must be formatted, lint-clean and tested. Unsafe Rust is forbidden by default; changing that policy requires an explicit architecture and security review.

All contributions are accepted under the repository's Apache-2.0 license.

