# Contributing to MAIA

Welcome, and thank you for considering contributing to the Monethic AI Auditor (MAIA). Whether you are reporting a bug, suggesting a feature, adding a new detector, or improving existing prompts, your contributions help make smart contract security more accessible.

## How to Contribute

### Bug Reports

If you encounter unexpected behavior, false positives, missed detections, or formatting issues:

1. Open an issue at [github.com/Monethic/monethic-maia/issues](https://github.com/Monethic/monethic-maia/issues)
2. Include the platform (EVM, Move-Aptos, Move-Sui), the mode used (recommended, ALL, NUCLEAR), and a description of the problem
3. If possible, include a minimal code sample that reproduces the issue

### Feature Requests

Open an issue with the `enhancement` label describing:

- What the feature would do
- Why it would be useful
- Any implementation ideas you have

### New Detectors

Adding new detectors is one of the most impactful contributions. See [maia-detector.md](maia-detector.md) for the detector format specification.

### Prompt Improvements

The audit pipeline is driven by prompts in the `prompts/` directory. If you find ways to reduce false positives, improve finding quality, or make the pipeline more efficient, submit a PR with your changes and a description of the improvement.

## Development Setup

1. Clone the repository:

```bash
git clone https://github.com/Monethic/monethic-maia.git
cd monethic-maia
```

2. Install as a Claude Code skill for testing:

```bash
cp -r . ~/.claude/skills/monethic_maia
```

3. Test with a sample smart contract project by running `/monethic_maia` inside the project directory.

## Adding New Detectors

Follow the detector format in [maia-detector.md](maia-detector.md):

1. Create the detector entry in the appropriate `{platform}/knowledge/checklists/categories/CAT-{CAT}.md`
2. Follow the format defined in [maia-detector.md](maia-detector.md)
3. Update `index.md`, `rulepack.md`, and `checklist_router.md`
4. Test by running MAIA on a sample project containing the vulnerability

## Code Style

- **Follow existing patterns.** Look at existing detectors and prompts for format and tone.
- **Sentence case titles.** Use "Privileged function access control" not "Privileged Function Access Control".
- **Concrete code examples.** Every detector pattern must include compilable (or near-compilable) vulnerable and fixed code.
- **Mechanical detection steps.** Write detect steps so they can be followed without domain intuition.
- **Specific counter-evidence.** State exactly what implementation elements negate a finding.
- **Minimal patterns.** Show only the code relevant to the vulnerability -- strip unrelated logic.

## Pull Request Process

1. **Fork** the repository
2. **Create a branch** for your changes (`git checkout -b add-detector-xyz`)
3. **Make your changes** following the style guidelines above
4. **Test** by running MAIA on a sample project to verify your changes work correctly
5. **Submit a pull request** with a clear description of what you changed and why

For new detectors, include in your PR description:

- The vulnerability class the detector covers
- The platform(s) it applies to
- A sample Solidity/Move snippet that triggers the detector

## Code of Conduct

- Be respectful and constructive in all interactions
- Focus feedback on the work, not the person
- Assume good intent from other contributors
- Help newcomers get started

## License

By contributing to MAIA, you agree that your contributions will be licensed under the [AGPL-3.0](LICENSE) license, the same license as the project.
