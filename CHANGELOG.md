# Changelog

## Unreleased

- Swedish personnummer and samordningsnummer (`se-personnummer`): Luhn digit and birth date verified,
  coordination numbers (day + 60) and the `+` separator for people over 100 understood. Matched only next to a
  `personnummer` or `samordningsnummer` label, because Luhn alone passes too many ordinary numbers.
- SQL gate: `personnummer` and `samordningsnummer` are core columns.

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
