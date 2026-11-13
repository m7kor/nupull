# Contributing to Nupull

Thank you for your interest in contributing to **Nupull**!

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/m7kor/nupull.git
   cd nupull
   ```

2. **Set up Python environment (Python 3.10+ required, 3.12 recommended):**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -e .[gui,dev]
   ```

3. **Run Type Checking (Strict MyPy):**
   ```bash
   mypy tools/nup/nup
   ```

4. **Run Regression Tests:**
   ```bash
   python tests/regression.py
   ```

5. **Run GUI Smoke Tests:**
   ```bash
   python nup_gui.py --smoke --page auto
   python nup_gui.py --smoke --page batch
   python nup_gui.py --smoke --page patch
   python nup_gui.py --smoke --page export
   ```

## Code Guidelines

- **Clean Architecture**: Follow clean-room specifications (`SPEC.md`).
- **Atomic Operations**: Containers must always be written atomically (`.partial` + rename) with safe error cleanup.
- **Type Safety**: All new code in `tools/nup/nup` must pass strict `mypy` with zero warnings or errors.
- **Strict English ASCII**: Code, comments, CLI strings, and commit messages must be ASCII English only.
- **Legal Hygiene**: Never include proprietary Nintendo keys or copyrighted binaries.
