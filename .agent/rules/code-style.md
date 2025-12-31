---
trigger: always_on
---

# Code Style Guidelines

**Activation:** File glob patterns (_.py, _.js, \*.ts, src/**, tests/**)

---

## Python Detailed Standards

### Type Hints & Exception Handling

- Mandatory type hints for function signatures.
- Use specific exceptions: `except FileNotFoundError:` (O) / `except:` (X).

### Naming Conventions

- Variables/Functions: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private: `_leading_underscore`

---

## JavaScript/TypeScript Standards

- Group imports: External -> Types -> Internal.
- Use `async/await` over `.then()` chains.

---

## Testing Standards (pytest)

- Use class-based test suites.
- Utilize `@pytest.fixture` and `@pytest.mark.parametrize`.

---

## Code Comments Policy

- **Comment when:** Explaining non-obvious optimizations, referencing external papers (arXiv), or documenting HACK/workarounds.
- **Do NOT comment:** Stating the obvious or redundant docstrings.
