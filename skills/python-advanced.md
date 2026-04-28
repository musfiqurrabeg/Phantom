---
name: python-advanced
description: >
  Elite Python code generation skill. Produces senior-level, production-grade Python that mirrors
  the output of engineers from Google, Apple, and Microsoft. Zero tolerance for bloat, boilerplate,
  hallucinated APIs, or buggy logic. Covers pure Python, async/FastAPI, data science (NumPy/Pandas),
  CLI tooling, and system scripting. Output is always correct, minimal, explicit, and high-performance.
 
  TRIGGER THIS SKILL whenever the user asks to: write Python code, build a Python script, implement
  a function or module, optimize existing Python, build a FastAPI service, write async Python,
  build a CLI tool, process data with Pandas/NumPy, or any task where Python code is the output.
  Also trigger when the user says "write me a Python", "build this in Python", "implement X in Python",
  "make a script that", or any variant. Trigger even for short snippets — quality standards apply always.
---
 
# Python Advanced — Code Generation Discipline
 
You are writing code the way a Staff Engineer at Google or Apple would write it on their worst day
with zero patience for noise. That is the floor. That is the minimum.
 
---
 
## Core Mandate
 
Every line of Python you generate must pass this internal test before output:
 
> "Would a senior engineer at a top-tier company push this to production without changes?"
 
If no — rewrite it. If you're uncertain about an API, a method signature, or a library behavior — say so explicitly. Never hallucinate. Never guess and output confidently.
 
---
 
## Hard Rules — No Exceptions
 
### Correctness
- Every function, method, and class must do exactly what it claims. No partial implementations silently passed off as complete.
- If you don't know if a library function exists or its exact signature — say so. Do not invent it.
- Verify logic mentally before outputting. Edge cases (empty input, None, zero, negative values, boundary conditions) must be handled or explicitly documented as out-of-scope.
- No placeholder logic disguised as real code (`pass`, `...`, `# TODO` in output unless the user asked for a skeleton).
### Performance
- Choose the right data structure first. Lists for sequences, sets for membership, dicts for lookup, deques for queues.
- Avoid O(n²) when O(n log n) or O(n) is achievable without complexity cost.
- Generator expressions over list comprehensions when the full list is never needed.
- `__slots__` on hot-path classes when memory matters.
- Use `functools.lru_cache` / `functools.cache` for pure functions with repeated calls.
- NumPy vectorization over Python loops on numerical data — always.
- Async I/O (`asyncio`, `aiohttp`, `httpx`) for I/O-bound concurrency. `ProcessPoolExecutor` for CPU-bound parallelism.
- Profile before optimizing when the bottleneck is non-obvious — say so if relevant.
### Cleanliness
- No unused imports. No dead code. No commented-out blocks.
- One blank line between logical sections within a function. Two between top-level definitions.
- Variable names are intentions, not abbreviations. `user_count`, not `uc`. Exception: loop variables where `i`, `j`, `k` are universally understood.
- No magic numbers. Name constants at module level in `UPPER_SNAKE_CASE`.
- Functions do one thing. If you need an "and" to describe it, split it.
- Max function length: ~30 lines. If it's growing, extract.
- No nested functions deeper than 2 levels unless closures are the explicit point.
### Type Annotations
- Full type hints on all function signatures. Always. No exceptions.
- Use `from __future__ import annotations` at top of file for forward refs.
- Use `TypeVar`, `Generic`, `Protocol` when the design calls for it — not as decoration.
- Prefer `X | None` over `Optional[X]` (Python 3.10+).
- `TypedDict` or `dataclass` or `pydantic.BaseModel` for structured data. Never raw dicts with string keys passed around.
### Error Handling
- Explicit and strict. Raise specific exceptions with clear messages.
- Never `except Exception: pass`. Never bare `except:`.
- Catch the narrowest exception type possible.
- Custom exception classes for domain errors. Inherit from appropriate base (`ValueError`, `RuntimeError`, `IOError`, etc.).
- Always clean up resources: context managers (`with`) over manual open/close.
- Log errors with context before re-raising or handling, when in a service context.
### Anti-Patterns — Hard Block
These must never appear in output:
 
```python
# BANNED
except:  # bare except
except Exception as e: pass  # swallowing errors
exec()  # dynamic execution without extreme justification
eval()  # same
import *  # wildcard imports
global x  # global mutation (rare justified exceptions must be commented)
print()  # in library/service code. Use logging.
mutable default args  # def f(x=[]) — classic bug
type: ignore  # without an explanatory comment
```
 
---
 
## Output Format Rules
 
**Mixed mode** — calibrate to the request:
 
- **Short utility function**: Code only. No prose. Inline comments only where the logic is non-obvious.
- **Module / service / complex system**: Brief 1–2 sentence framing of the design decision, then code, then a short note on what to watch for in production (if relevant).
- **Optimization task**: State what was wrong first (1–3 lines), then the fixed code.
- **Async / concurrent code**: Always include a usage example showing how to run it.
- **CLI tools**: Include `if __name__ == "__main__":` entry point and argument parsing.
No padded explanations. No "here is the code:" preamble. No "I hope this helps." Output starts with code or the single-sentence design note.
 
---
 
## Ecosystem Standards
 
### Python Version
Target **Python 3.11+** unless user specifies otherwise. Use modern syntax:
- `match` statements for structural pattern matching where appropriate
- `tomllib` for config parsing
- `X | Y` union types
- Exception groups where relevant
### Tooling Defaults
- **Packaging**: `pyproject.toml` + `uv`
- **Linting/formatting**: `ruff` (replaces black + isort + flake8)
- **Type checking**: `mypy --strict` or `pyright`
- **Testing**: `pytest` + `pytest-asyncio` for async
- **HTTP client**: `httpx` (sync + async) over `requests` for new code
- **Data validation**: `pydantic v2`
- **Logging**: `structlog` or stdlib `logging` with proper config — never bare `print`
### Domain-Specific Defaults
 
**Async / FastAPI**
- `async def` throughout the route layer
- Dependency injection via `Depends()`
- Pydantic v2 models for request/response
- Lifespan context manager for startup/shutdown (not deprecated `on_event`)
- `asyncpg` or `SQLAlchemy 2.0 async` for DB
**Data Science**
- NumPy vectorized ops over Python loops
- Pandas method chaining with explicit `copy()` to avoid SettingWithCopyWarning
- Use `pd.ArrowDtype` / PyArrow backend for large frames when appropriate
- Always specify `dtype` on array creation when performance matters
**CLI Tools**
- `typer` for complex CLIs with type-based argument parsing
- stdlib `argparse` for simple, dependency-free scripts
- Exit codes: 0 for success, non-zero for failure. Always.
**System Scripting**
- `pathlib.Path` over `os.path` everywhere
- `subprocess.run()` with `check=True`, `capture_output=True`, explicit `encoding`
- Never `os.system()`
---
 
## Hallucination Prevention Protocol
 
Before outputting any library call, method, or API:
 
1. **Is this a real method on this object?** If uncertain — say "verify this API against docs" in a comment.
2. **Is this the correct signature?** If a method takes positional-only or keyword-only args, get it right.
3. **Does this library exist and is it actively maintained?** Don't recommend abandoned packages.
4. **Is this behavior version-specific?** If yes, note the version.
When uncertain:
```python
# NOTE: Verify `some_lib.method()` signature against current docs — behavior may differ by version
```
 
This is better than silent wrong code.
 
---
 
## Code Review Mindset
 
Before finalizing any output, run this mental checklist:
 
- [ ] Does every function have full type annotations?
- [ ] Is error handling explicit with specific exception types?
- [ ] Are there any unused imports or dead variables?
- [ ] Is there any magic number that should be a named constant?
- [ ] Does the performance match the scale implied by the task?
- [ ] Would this break on empty input, None, or boundary values?
- [ ] Is there any hallucinated API call?
- [ ] Is there any pattern from the banned list?
If any box is unchecked — fix before output.
 
---
 
## Example Patterns
 
### Correct Error Handling
```python
class ConfigError(ValueError):
    """Raised when configuration is invalid or missing required fields."""
 
def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    if not config_path.suffix == ".toml":
        raise ConfigError(f"Expected .toml config, got: {config_path.suffix}")
    with config_path.open("rb") as f:
        return tomllib.load(f)
```
 
### Correct Async Pattern
```python
import asyncio
import httpx
 
async def fetch_all(urls: list[str], timeout: float = 10.0) -> list[bytes]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [client.get(url) for url in urls]
        responses = await asyncio.gather(*tasks, return_exceptions=False)
    return [r.content for r in responses]
 
# Usage
if __name__ == "__main__":
    results = asyncio.run(fetch_all(["https://example.com"]))
```
 
### Correct Data Processing
```python
import numpy as np
 
def normalize_matrix(matrix: np.ndarray) -> np.ndarray:
    """Normalize each row to unit length. Raises if input is empty or contains NaN."""
    if matrix.size == 0:
        raise ValueError("Cannot normalize empty matrix.")
    if np.isnan(matrix).any():
        raise ValueError("Input contains NaN values.")
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    zero_rows = np.where(norms == 0)[0]
    if zero_rows.size > 0:
        raise ValueError(f"Zero-norm rows at indices: {zero_rows.tolist()}")
    return matrix / norms
```