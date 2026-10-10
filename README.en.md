<!-- markdownlint-disable MD033 -->
# vtotp

English | [日本語](README.md)

A high-security CLI TOTP (Time-based One-Time Password) authenticator built with practicality and robustness on Windows in mind.

It physically separates the master key from encrypted data, ensures plaintext secrets are never persisted to disk and never leak into display outputs or logs (Zero Leakage Rule), and fully handles Windows-specific path-input quirks.

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
- **Microsoft Store & winget official distribution**: Ships as a Store-signed MSIX package that eliminates Windows 11 Smart App Control (SAC) and SmartScreen unsigned binary warnings. Integrated with Windows execution aliases (`AppExecutionAlias`), making the `vtotp` command globally available from any terminal immediately after installation without manual `PATH` setup.

---

## Requirements

- Python 3.11 or later (only when running from source)
- Windows / macOS / Linux (prebuilt binaries are currently Windows x64 only)

---

## Installation and Distribution Formats

vtotp ships in **four distribution formats**, allowing you to choose the best option for your environment and workflow. All formats provide identical functionality (Zero Leakage, encryption, exit codes, etc.) — they differ primarily in installation method, startup performance, and security signing characteristics. For daily use on Windows, the **Store Edition (MSIX / winget)** is recommended for a seamless, warning-free experience without manual `PATH` setup.

| Format | Artifact / Install Method | Startup Speed | Security & Signing Characteristics | Recommended For |
| --- | --- | --- | --- | --- |
| ① **Store Edition**<br>(Recommended for Windows) | Microsoft Store<br>`winget install vtotp` | **Instant**<br>(~0.05–0.1s, no runtime extraction) | **No SmartScreen / SAC warnings**<br>(Store automatic code signing) | **All Windows users**.<br>Zero security warnings, zero manual `PATH` setup, seamless terminal integration |
| ② **Standalone ZIP** | `vtotp-windows-x64.zip`<br>(folder bundle) | **Instant**<br>(~0.05–0.1s, no runtime extraction) | Low AV heuristic risk (no temp dropping); may require manual override on unsigned runs | Environments where Microsoft Store is unavailable, or power users who prefer manual folder placement & `PATH` setup |
| ③ **Onefile EXE** | `vtotp.exe`<br>(single binary) | Extraction overhead<br>(delay from runtime unpack & AV scan) | Drops DLLs to temp folder at runtime; more susceptible to AV scanning delays | Portable use (e.g., USB drive) where you want a single `.exe` file without unpacking |
| ④ **Source install**<br>(Python package) | `pip install -e .` | Normal<br>(standard Python runtime startup) | Depends on the OS's own Python runtime | Linux/macOS users, and developers who want to inspect or modify the code directly |

### ① Store Edition (MSIX / winget: Recommended for Windows)

The easiest, safest, and officially recommended installation method on Windows.

- **Microsoft Store**: One-click install and automatic background updates via the Microsoft Store.
- **winget (Windows Package Manager)**: Install with a single command from your terminal:

```powershell
# Install via winget
winget install vtotp
```

> **Transparent CLI Execution (No PATH Setup Required)**:
> Upon installation, Windows App Execution Alias (`AppExecutionAlias`) automatically makes `vtotp` and `vtotp.exe` globally available in any terminal (PowerShell, Command Prompt, Windows Terminal) without modifying your `PATH` environment variable.
> Furthermore, with Microsoft Store's automatic code signature, you will never see Windows SmartScreen warnings or Windows 11 Smart App Control (SAC) execution blocks.

### ② Standalone ZIP (Fast & Portable Everyday Use)

Download `vtotp-windows-x64.zip` from [GitHub Releases](https://github.com/hammer-app/vtotp-cli/releases) and extract it to any folder.

```powershell
# Example: extracting to C:\Tools\vtotp\
Expand-Archive vtotp-windows-x64.zip -DestinationPath C:\Tools\vtotp

# Add that folder to PATH to run `vtotp` from anywhere
C:\Tools\vtotp\vtotp.exe --version
```

The folder contains `vtotp.exe` plus its dependent DLLs and the Python runtime. Because nothing is extracted at runtime, this starts instantly and is the lowest-risk way to run vtotp.

### ③ Onefile EXE (Portable, Single File)

Download the single-file `vtotp.exe` from the same [Releases page](https://github.com/hammer-app/vtotp-cli/releases) and place it in any folder — no extraction needed.

```powershell
# Example: running without adding it to PATH
C:\Tools\vtotp\vtotp.exe --version
```

Runs, especially when intercepted by a security product's scan, may take a moment to self-extract, but there's no folder to manage or install step — just one portable file.

Neither binary format requires pip or a virtual environment. Everywhere the quickstart below shows `vtotp`, you can substitute `vtotp.exe`.

### ④ Source install (Python / pip)

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

Registers a Base32-encoded TOTP secret.

For manual use, entering the secret via the interactive prompt (masked input) is recommended as it never touches your terminal history. For scripts and automated pipelines, secrets can be passed via standard input using the `--stdin` option.

<!-- Note -->
> **Note**: Specifying secrets via CLI arguments (`--secret` / `-s`) has been completely removed for security reasons, preventing plaintext secrets from leaking into shell history (`.bash_history`, PowerShell Readline history) or process lists (`ps`, `Get-Process`).
<!-- Warning -->
> **Warning (Shell history precaution)**: In an interactive terminal, piping secrets directly like `echo "SECRET" | vtotp add ... --stdin` will leave the plaintext secret in your shell's command history. When piping via stdin, use a temporary file (securely wiped after registration) or pipe from a password manager / secure secret store.

```powershell
# Enter interactively (recommended: masked input, never touches shell history)
vtotp add github
vtotp add aws --issuer Amazon

# Pass via standard input pipe (PowerShell: piping from a file or secret store)
Get-Content secret.txt | vtotp add aws --stdin
Get-Content secret.txt | vtotp add aws --issuer Amazon --stdin

# (Reference) Linux / macOS file pipe example:
# cat secret.txt | vtotp add aws --stdin
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
vtotp add aws --stdin -l ja

# Not supported (rejected with exit code 2)
vtotp get -l ja github
vtotp get --key "PATH" github
vtotp add --stdin aws
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
