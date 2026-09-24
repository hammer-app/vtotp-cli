English | [日本語](README.md)

# vtotp

A high-security CLI TOTP (Time-based One-Time Password) authenticator built with practicality and robustness on Windows in mind.

It physically separates the master key from encrypted data, guarantees that secrets never appear in memory dumps or logs (Zero Leakage Rule), and fully handles Windows-specific path-input quirks.

---

## Key Features

- **Strong encryption with key separation**: TOTP secrets are stored encrypted with AES-256-GCM. The encrypted data and the 32-byte master key used to decrypt it can be kept in two separate, secure locations (removable media, a OneDrive Vault, etc.).
- **Zero Leakage Rule (secrets never leak)**:
  - Only the generated 6-digit code is written to `stdout`, so piping to another command or a clipboard tool (`vtotp github | clip`) is always safe.
  - The remaining-time bar, progress output, prompts, and warning/error messages are all routed to `stderr`.
  - Neither the master key nor a plaintext secret is ever printed on success or on failure.
- **Full English/Japanese localization**: help text, prompts, and error messages can be switched between English and Japanese (`-l` / `--lang`, an environment variable, `config.json`, or the OS locale, resolved in that priority order).
- **Windows-friendly**:
  - Automatically strips surrounding quotes (`"` or `'`) and stray whitespace that Windows Explorer's "Copy as path" often introduces.
  - Catches Windows-specific invalid-path errors (`[WinError 123]`) and OS errors, and never lets a raw Python traceback reach the screen.
- **Ergonomic by default**:
  - The most common operation — generating a code — doesn't need a subcommand at all (`vtotp <service>` is enough).
  - Master key rotation keeps up to 3 automatic generations of backups.
- **Tamper-resistant native binaries**: distributed binaries are built with **Nuitka**, which transpiles the Python source into C-equivalent code and compiles it to native machine code, rather than bundling Python bytecode the way PyInstaller does. This makes recovering the original source with a typical Python bytecode decompiler impractical, giving the binary real tamper resistance.

---

## Requirements

- Python 3.11 or later (only when running from source)
- Windows / macOS / Linux (prebuilt binaries are currently Windows x64 only)

---

## Installation and Distribution Formats

vtotp ships in **three distribution formats**, so you can pick the one that fits your environment and workflow. All three behave identically (Zero Leakage, encryption, exit codes, etc.) — only the startup characteristics differ.

| Format | Artifact | Startup speed | Security characteristics | Recommended for |
| --- | --- | --- | --- | --- |
| ① **Standalone ZIP** (recommended) | `vtotp-windows-x64.zip` (a folder of files) | **Instant** (no perceptible lag; no extraction happens at runtime) | Doesn't drop files into a temp folder at runtime, so it's the least likely to trigger AV heuristics | Users who call `vtotp` from a terminal all day and want it on `PATH` for the fastest possible startup |
| ② **Onefile EXE** | `vtotp.exe` (a single file) | Extraction overhead (startup delay due to runtime extraction or security scanning) | Extracts DLLs to a temp folder at runtime, so it's more exposed to AV scanning/detection | Users who want a single `.exe` they can drop on a USB drive or into any folder, with no `PATH` setup or unpacking |
| ③ **Source install** (Python package) | `pip install -e .` | Normal (standard Python runtime startup) | Depends on the OS's own Python runtime | Linux/macOS users, and developers who want to read or modify the code directly |

### ① Standalone ZIP (recommended, fastest)

Download `vtotp-windows-x64.zip` from [GitHub Releases](https://github.com/hammer-app/vtotp-cli/releases) and extract it to any folder.

```powershell
# Example: extracting to C:\Tools\vtotp\
Expand-Archive vtotp-windows-x64.zip -DestinationPath C:\Tools\vtotp

# Add that folder to PATH to run `vtotp` from anywhere
C:\Tools\vtotp\vtotp.exe --version
```

The folder contains `vtotp.exe` plus its dependent DLLs and the Python runtime. Because nothing is extracted at runtime, this starts instantly and is the lowest-risk way to run vtotp.

### ② Onefile EXE (portable, single file)

Download the single-file `vtotp.exe` from the same [Releases page](https://github.com/hammer-app/vtotp-cli/releases) and place it in any folder — no extraction needed.

```powershell
# Example: running without adding it to PATH
C:\Tools\vtotp\vtotp.exe --version
```

Runs, especially when intercepted by a security product's scan, may take a moment to self-extract, but there's no folder to manage or install step — just one portable file.

Neither format requires pip or a virtual environment. Everywhere the quickstart below shows `vtotp`, you can substitute `vtotp.exe`.

### ③ Source install (Python / pip)

Create a virtual environment and install in editable or normal mode.

```powershell
# Clone the repository
git clone https://github.com/hammer-app/vtotp-cli.git
cd vtotp-cli

# Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install
pip install -e .
```

Once installed, the `vtotp` command is available.

---

## Quickstart

### 1. Initialize (`init`)

Creates a master key and initializes the encrypted storage. If `-l` / `--lang` is omitted, `init` prompts interactively for a display language (`en`/`ja`); leaving that prompt blank accepts the already-resolved default.

```powershell
# Prompt interactively for both the key output path and the display language
vtotp init

```

When prompted, provide the key's output path (e.g. `"C:\Users\<user>\OneDrive\Personal Vault\master.key"`). Surrounding quotes are stripped automatically even if pasted in.

```powershell
# Specify the output path and language directly as arguments (-k/--key, -l/--lang; no prompts)
vtotp init --key "C:\Users\<user>\OneDrive\Personal Vault\master.key" -l ja
vtotp init -k "D:\USB\master.key" -l en

```

### 2. Register a service (`add`)

Registers a Base32-encoded TOTP secret. Pass it directly with `--secret` (short form: `-s`).

```powershell
# Enter it interactively (recommended: it never touches your shell history)
vtotp add github

# Pass it directly as an argument (--secret / -s)
vtotp add aws --secret JBSWY3DPEHPK3PXP --issuer Amazon
vtotp add aws -s JBSWY3DPEHPK3PXP --issuer Amazon

```

### 3. Generate a TOTP code (`generate`, aliases: `get` / `-g`, or the shorthand form)

Pass just the service name to get a 6-digit code immediately. `generate` has two aliases, `get` and `-g`.

```powershell
# Shorthand form (best for everyday use — a bare service name is treated as generate)
vtotp github

# Explicit subcommand
vtotp generate github

# Aliases (identical behavior to generate)
vtotp get github
vtotp -g github

# Copy straight to the clipboard (PowerShell)
vtotp github | Set-Clipboard

```

### 4. List registered services (`list`, alias: `ls`)

Shows the registered service names and issuers (never the secrets). `ls` is an alias for `list`.

```powershell
vtotp list
# ls is an alias for list
vtotp ls

```

### 5. Remove a service (`remove`, alias: `rm`)

Safely deletes a service you no longer need. `rm` is an alias for `remove`. Skip the confirmation prompt with `--force` (short form: `-f`).

```powershell
# With a confirmation prompt
vtotp remove github

# Skip confirmation and delete immediately (--force / -f)
vtotp remove github --force
vtotp remove github -f

# rm is an alias for remove (identical behavior)
vtotp rm github --force

```

### 6. Rotate the master key (`rekey`)

Re-encrypts the storage under a freshly generated master key (the old key is automatically preserved as `<key_path>.1`).

```powershell
vtotp rekey

```

---

## Command Syntax and Option Placement

vtotp's command line follows two rules, chosen to keep behavior predictable for pipelines and scripts:

1. **The first argument is fixed**: the first argument must be a reserved subcommand or a service name (shorthand form). Except for `-h` / `--help` / `--version`, no option may appear before it.
2. **Options are placed after SERVICE**: for commands that take a `SERVICE` (`generate` / `get` / `add` / `remove` / `rm`), `SERVICE` must immediately follow the subcommand, and any options may only appear after it.

```powershell
# Valid (SERVICE right after the subcommand; options go afterward, in any order)
vtotp get github -l ja
vtotp get github --key "PATH" -l ja

# Not supported (rejected with exit code 2)
vtotp get -l ja github
vtotp get --key "PATH" github

```

---

## Display Language (`-l` / `--lang`)

The CLI's display language (help text, prompts, error messages, etc.) fully supports English (`en`) and Japanese (`ja`), resolved in this priority order:

1. The command-line argument (`-l` / `--lang <en|ja>`) — placed after `SERVICE`/options for the relevant subcommand
2. The `VTOTP_LANG` environment variable
3. The `language` setting in `config.json`
4. The OS locale environment (`LANG`, `LC_ALL`, the OS default locale)
5. The fallback default language (`en`)

```powershell
# Show output in Japanese for a single invocation
vtotp list -l ja
vtotp github -l ja

# Switch permanently via an environment variable (e.g. in your shell profile)
$env:VTOTP_LANG = "ja"

```

### Checking and permanently changing the language (`config`)

```powershell
# Show the currently resolved key path, storage path, and display language
vtotp config

# Persist the language setting to config.json (shortcut syntax)
vtotp config -l ja

# Persist the language setting to config.json (standard syntax; behaves identically to the line above)
vtotp config set language en

```

`config -l <en|ja>` and `config set language <en|ja>` are fully equivalent — same saved content, same displayed message, same exit code. The shortcut is convenient for the language switch you'll make most often day to day.

---

## Configuration and Resolution Priority

The master key's location is resolved in this priority order:

1. The command-line argument (`-k PATH` or `--key PATH`)
2. The `VTOTP_KEY_PATH` environment variable
3. The config file saved during `init` (`~/.vtotp/config.json`)

The encrypted storage file's location can be overridden temporarily with `--storage PATH` (this is never written to `config.json`). If omitted, it falls back to `config.json`'s `storage_path`, and if that's also absent, to `vtotp-secrets.enc` in the same directory as `config.json`.

Check the current configuration at any time with:

```powershell
vtotp config

```

---

## Exit Codes

When calling vtotp from a script, use these exit codes to determine the result:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General error (e.g. a failed file operation) |
| 2 | CLI argument error |
| 3 | Key file missing or invalid |
| 4 | Encrypted data corrupted or decryption failed |
| 5 | The requested service is not registered |
| 6 | The TOTP secret has an invalid format |
| 7 | Cancelled by the user |

---

## Development and Build

- Development environment setup and testing instructions: [CONTRIBUTING.md](CONTRIBUTING.md)
- Binary build and CI specifications: [docs/BUILD.md](docs/BUILD.md)

This project continuously maintains testing, static analysis, and build verification, with a policy of keeping 100% coverage and zero warnings.

---

## License

MIT License
