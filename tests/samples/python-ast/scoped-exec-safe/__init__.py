"""Fixture: exec() inside a function — only runs if the function is called.
PYSRC-001 (regex) flags this anyway (FP); PYAST-003 (scope-aware) MUST NOT.
This fixture is the canonical demonstration of why we added the AST scanner.
"""


def maybe_run_user_code(snippet: str) -> None:
    # This exec is inside a function body — not import-time. Library design
    # like sympy's `lambdify` does this; flagging it as RCE is a false positive.
    exec(snippet)


__all__ = ["maybe_run_user_code"]
