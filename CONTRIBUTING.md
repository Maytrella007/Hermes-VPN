# Contributing

Thanks for looking. A few things make a change easy to accept.

## Running the tests

No dependencies, no network, no Hermes required. From the repo root:

```bash
python -m unittest discover -s tests -t .
```

That is exactly what CI runs, on Python 3.11, 3.12 and 3.13.

**If a result looks impossible, clear the bytecode cache first.** A stale `.pyc`
has told a convincing lie here more than once:

```bash
rm -rf __pycache__ tests/__pycache__
python3 -B -m unittest discover -s tests -t .
```

`pytest` works too (`pyproject.toml` puts the repo root on the path), but the
suite is plain `unittest` and does not need it.

## The privileged helpers

`contrib/` holds the host side, including the root-owned `vpn-exit`. A change to
any of those scripts is a change to the one thing that runs as root, so it gets
read the way root-owned code should be. `tests/test_install.py` drives the real
installer; keep it passing.

## Style

- **Comments describe the code, not its history.** No "changed X to Y", no dates,
  no "previously". If a line needs a reason, give the reason.
- Measured against the voice of the Python standard library and urllib3: first
  person where it reads naturally, most comments a single line, and no em-dashes
  in code.
- **Verify, never assume; fail closed.** The two rules the plugin follows are the
  two rules a change should keep. A new path that could leave the browser on the
  host's own address is the bug this project exists to prevent.

## Before a pull request

- The suite is green with a clean cache on at least one of the CI versions.
- A behaviour change comes with a test that fails without it. Mutation is the
  bar: if breaking the new code does not break a test, the test is not testing it.
- The scanner verdict stays `safe` (`hermes plugins validate`).
