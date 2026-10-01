# Project Guidelines: vtotp

Custom CLI TOTP Authenticator built in Python.
Refer to @docs/REQUIREMENTS.md for functional requirements and @docs/DESIGN.md for detailed architectural design specs.

## Operational Rules & Behavioral Guidelines

- **No Direct Document Modification:**
  - Do not directly edit or commit documentation files (`docs/REQUIREMENTS.md`, `docs/DESIGN.md`, `README.*`, `SECURITY.md`, etc.).
  - If discrepancies are identified between documentation and actual implementation or CLI behavior, report them in review steps instead of modifying files directly.
- **Human-Led Git Operations:**
  - For change safety and governance, Git commits and pushes must strictly be performed by human developers (unless explicitly instructed for exceptional cases such as automated CI repair).
  - Claude Code must report verification results upon task completion and handle PR creation only after human developers have pushed the commits.

## Command Guidelines & Commands

- **Install in Editable Mode:** `pip install -e .`
- **Run Tests:** `pytest`
- **Run Tests with Coverage:** `pytest --cov=src/vtotp`
- **Format Code:** `black src tests`
- **Lint Code:** `flake8 src tests` / `mypy src`

## Code Style & Architecture Standards

### 1. General Python Standards

- **Python Target:** Python 3.11+
- **Type Binds:** Strict static type annotations for all functions, arguments, and return types.
- **Code Style:** PEP 8 compliance. Clean, modular, single-responsibility functions.
- **Imports Order:**
  1. Standard library modules (`os`, `sys`, `json`, `argparse`, etc.)
  2. Third-party dependencies (`cryptography`, `pyotp`, etc.)
  3. Internal package modules (`vtotp.*`)

### 2. Architecture Constraints (Strict Compliance with `DESIGN.md`)

- **Package Layout:** Follow the modular structure in `DESIGN.md` Section 2 (`cli/`, `core/`, `domain/`, `infrastructure/`).
- **CLI Parsing & Shorthand Fallback:**
  - Standard commands & aliases: `init`, `generate`, `get`, `-g`, `add`, `remove`, `rm`, `list`, `ls`, `rekey`.
  - Non-reserved first arguments must automatically fallback to `generate <service>` via `CliHandler.normalize_argv`.
- **Encryption & Key Management:**
  - Cipher: `AES-256-GCM` using `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
  - Master Key: 32 bytes binary stored at external `key_path`.
  - Nonce: 12 bytes generated freshly per encryption operation.
- **Atomic Operations & Rekeying:**
  - Secret data files must be written to temporary files first, then atomically swapped via `os.replace`.
  - Key rotation (`rekey`) rotates the master key file up to 3 generations (`<key_path>.1`, `<key_path>.2`, `<key_path>.3`).
  - Secret data (`vtotp-secrets.enc`) is re-encrypted with the new key in-place and DOES NOT create `.1` data backups.

### 3. Security & Information Protection

- **Zero Leakage Rule:** Decrypted JSON payloads, secret keys, master keys, and OTP seeds MUST NEVER be printed to standard logs, exception messages, or tracebacks.
- **Config Security:** `config.json` must ONLY store file paths (`key_path`, `storage_path`), NEVER raw key bytes or secrets.
- **Output Streams:**
  - `stdout`: Strictly dedicated to command outputs (e.g., raw 6-digit TOTP code, simple list formats).
  - `stderr`: Dedicated to user prompts, interactive warnings, error messages, and debug logs.

### 4. Error Handling & Exit Codes

- Use custom exception hierarchy derived from `TotpCliError` (`KeyNotFoundError`, `StorageCorruptedError`, `ServiceNotFoundError`, etc.).
- Map exceptions strictly to specified exit codes (0: Success, 1: General, 2: CLI Arg, 3: Key Err, 4: Storage/Decrypt Err, 5: Service Not Found, 6: Invalid Secret, 7: Cancelled).
- `CliHandler` must intercept all `TotpCliError` exceptions and gracefully map them to user-friendly `stderr` messages.

### 5. Testing Requirements

- Unit tests must be placed in `tests/unit/` and integration tests in `tests/integration/`.
- Maintain 100% code coverage across the entire codebase (`src/vtotp`).
- Always run `pytest` and verify clean output before completing any task.
