# Contributing

Thank you for helping improve `workflow-guard`.

## Development setup

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
workflow-guard . --fail-on medium
```

## Pull requests

1. Open an issue for behavioral changes or new rules so the expected signal and false-positive risk can be discussed.
2. Add or update tests for every behavior change.
3. Keep rules evidence-based and include an actionable recommendation.
4. Avoid network access and new runtime dependencies unless the benefit clearly outweighs the maintenance cost.
5. Update `CHANGELOG.md` for user-visible changes.

By contributing, you agree that your contribution is licensed under the MIT License.

