# Changelog

## 0.3.0 (2026-10-24)

A security review release. Everything below was found by reviewing the 0.2.0 code and docs against
the agents' current hook documentation and by trying to get data past the gate with synthetic values.

### Fixed: ways to get past or disable the gate

- **Module shadowing.** The hook was launched with `python -m pii_gate`, which puts the agent's
  working directory first on `sys.path`, so a `pii_gate/` folder or a `json.py` written into the
  project replaced the gate. The installer now launches the `pii-gate` console script (or the
  interpreter with the working directory removed from `sys.path`), and writes to such files are
  `tamper` findings.
- **Launch failures and timeouts.** A hook that could not start, or timed out, let the call through
  in every agent. Claude Code entries now carry `onFailure: "block"` and use the exec form (no shell,
  so they also work on Windows without Git Bash); Codex entries are wrapped so that a missing
  interpreter still exits 2. Payloads above 8 MB are blocked without scanning.
- **Untrusted project config.** The first `.pii-gate.json` found won, including one in a repository the
  agent had just cloned. The home file is now the base; a project file may only tighten the gate, and
  the project root is the session root, not the directory the agent has changed into.
- **`allow_paths` escapes.** `tests/../src/x` matched `tests/*`; a bare `README.md` pattern matched
  every README anywhere; absolute paths outside the project matched relative patterns; remote write
  tools (an MCP "create file" call) with a `path` argument skipped scanning entirely. All fixed.
- **Shell overwrites of the gate's files** through heredocs, `.NET` calls, `dd`, `install` or any tool
  not on the old write-token list. A command that mentions a gate file is now blocked unless it is a
  single read-only command.
- **Self-removal.** `pii-gate uninstall`, `pip install/uninstall ... pii-gate`, `disableAllHooks`,
  `codex_hooks=false`, `claude --bare` are `tamper` findings.
- **A quadratic regex** in the SQL gate (`select` without `from`) stalled the hook on a 100 KB input;
  an unclosed `/*` comment did the same. Both are linear now.
- **Shell tools only by name.** `Monitor`, MCP shells (`command`/`cmd` arguments, argv lists) and
  Gemini's `run_shell_command` now get the command rules. Numbers and dict keys in tool arguments
  are scanned. Codex `apply_patch` "Move to:" and `++` content lines are handled.
- **Exfiltration coverage**: `curl -X POST ... < file`, bundled short flags, `-K`, `--data-ascii`,
  `wget --body-data`, PowerShell abbreviations and .NET uploaders, mail and clipboard commands,
  `ssh ... < file`, `gh gist/release/api`, `glab`, `azcopy`, `gcloud storage`, `s3cmd`, `mc`, `b2`,
  `npm publish`, `twine upload`, `docker push`, `kubectl cp`, tunnels (`ngrok`, `cloudflared`,
  `ssh -R`), `/dev/tcp`, `python -m http.server`, any outbound call fed from a file or a sub-command,
  and quoting/backslash/`${IFS}` obfuscation of command names. `git svn dcommit` and `hub push` count
  as pushes.
- Windows: the hook reads stdin as UTF-8 bytes and writes UTF-8 regardless of the console code page,
  so a non-ASCII reason can no longer turn a block into a crash. Decision log lines no longer end in
  `\r\r\n`.

### Added

- **Swedish personnummer / samordningsnummer** (`se-personnummer`): Luhn digit and birth date
  verified, coordination numbers (day + 60) and the `+` separator for people over 100 understood;
  matched only next to a `personnummer` or `samordningsnummer` label. `personnummer` and
  `samordningsnummer` are core SQL columns. Contributed by bh-official (#7).
- **Gemini CLI** support (`pii-gate install gemini`): `BeforeTool` and `BeforeAgent` events,
  `run_shell_command`, `write_file`, `replace`, `read_file`.
- **Read gate** (`read`, default block): a `Read`/`read_file` of a local file whose content holds
  block-level personal data or secrets is stopped before it reaches the model. `Artifact` and
  `SendUserFile` are checked the same way under `exfil`.
- Claude Code: a blocked prompt is no longer echoed back into the transcript (`suppressOriginalPrompt`).
- Detectors: Mastercard 2-series, MIR and Troy card prefixes; IBAN registry lengths for all countries,
  lowercase and dashed IBANs, trailing tokens; Stripe, GitLab, npm, PyPI, Hugging Face, SendGrid,
  Slack webhook, Telegram, age, Azure and AWS secret keys, credentials in URLs and `Authorization`
  headers, PGP private keys; invisible characters (zero-width, soft hyphen) are removed before
  matching; `secret-assign` understands `DB_PASSWORD=`, JSON, YAML, Go and PHP forms.
- SQL gate: column names are matched on their parts (`tcKimlikNo`, `[TC Kimlik No]`, `doğum_tarihi`),
  single-quoted SQL in shell one-liners and `sp_executesql` is scanned, `--flag` is not a comment,
  `EXTRACT(... FROM ...)` no longer ends the select list, `RETURNING`/`OUTPUT` lists and
  `COPY`/`\copy`/`bcp` exports of person tables are covered, `#temp` tables and `[p].*` are seen,
  more revealing-nothing wrappers are allowed (`DATEDIFF(year, ...)`, hashes, `AVG(salary)`).
- `pii-gate scan`: whole-file scanning (multi-line SQL), UTF-16 files, skipped files are reported,
  `--max-bytes`, a missing path is an error, robust `--staged` parsing (renames, spaces, `++` lines,
  non-ASCII names). A `.pre-commit-hooks.yaml` for the pre-commit framework.
- `pii-gate status` reports the config files consulted and whether the installed hook program exists.
- `docs/threat-model.md`.
- Config: unknown keys are errors; `PII_GATE_CONFIG` pointing to a missing file is an error;
  `trust_project_config`.

### Changed

- `pii-gate install claude --project` writes `.claude/settings.local.json`.
- The deny message no longer claims that data "must not leave this machine"; it says the call may
  carry data out of the session, which is what the gate can judge.
- README rewritten with a threat model, honest limits and corrected performance figures.

## 0.2.0 (2026-10-23)

- National IDs of four more countries, each with its checksum: Spanish DNI/NIE (`es-dni`),
  Italian codice fiscale with omocodia (`it-cf`), Dutch BSN (`nl-bsn`) and Polish PESEL (`pl-pesel`).
  BSN and PESEL are matched only next to their label, because their checks alone pass too many
  ordinary numbers.
- SQL gate: `dni`, `nie`, `nif`, `codice_fiscale`, `bsn`, `burgerservicenummer` and `pesel` are core columns.

## 0.1.0 (2026-10-23)

First release.

- Hook for Codex CLI and Claude Code (`PreToolUse`, `UserPromptSubmit`), exit-code-2 protocol, fail closed.
- Detectors: Turkish national ID (checksum), IBAN (mod-97, country lengths), payment cards (Luhn),
  e-mail, phone, secrets (private keys, AWS, OpenAI/Anthropic, GitHub, Slack, Google, JWT, clear-text assignments).
- Shell rules: uploads and outbound calls carrying sensitive data, `git push`, tamper protection for the
  gate's own configuration and hook settings.
- Two-tier SQL gate: core columns, context columns, person tables, non-revealing wrappers.
- `.pii-gate.json` configuration with rule levels, allow lists, e-mail domains and SQL extensions.
- CLI: `check`, `scan` (files and `--staged`), `install`, `uninstall`, `status`.
- Decision log with counts only.
