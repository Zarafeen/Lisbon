# Contributing to Lisbon

Thanks for contributing to Lisbon.

## Before You Start

- Open an issue first for large changes
- Keep changes focused and easy to review
- Do not mix unrelated fixes in one pull request
- Be careful with code that changes system settings, deletes files, or touches security-sensitive paths

## Development Setup

```bash
git clone https://github.com/Zarafeen/Lisbon.git
cd Lisbon
pip install -r requirements.txt
```

Basic validation:

```bash
python -m py_compile src\__init__.py src\agent.py src\auditor.py src\advanced_protection.py src\utils.py setup.py
```

## Pull Requests

- Use a clear branch name
- Explain what changed and why
- Include manual test notes if you changed runtime behavior
- Mention any Windows-specific assumptions
- Update the README or config examples when behavior changes

## Good First Contributions

- improve documentation
- add tests
- reduce false positives in malware scanning
- improve Windows compatibility and logging
- tighten input validation without breaking core commands

## Safety Expectations

- Do not submit changes that auto-delete user files by default
- Prefer quarantine, confirmation, or opt-in behavior for destructive actions
- Treat malware detections as potentially noisy unless the rule confidence is strong

## Code Style

- Keep functions small and readable
- Prefer explicit behavior over clever shortcuts
- Add comments only when they help explain non-obvious logic
- Keep configuration-driven behavior in `cofigs/settings.yaml` when practical
