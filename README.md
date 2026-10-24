# pii-gate

**A fail-closed personal-data gate for AI coding agents.**

One small hook, installed into [Codex CLI](https://developers.openai.com/codex) and
[Claude Code](https://code.claude.com), that stops the agent *before* it runs a shell command, writes
a file, calls the web or sends a prompt that would leak personal data or secrets.

[![ci](https://github.com/sdursun1979/pii-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/sdursun1979/pii-gate/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pii-gate)](https://pypi.org/project/pii-gate/)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![pii-gate check blocks a curl upload, a SELECT of personal columns and a Turkish national ID, and lets a COUNT(*) through](https://raw.githubusercontent.com/sdursun1979/pii-gate/main/docs/demo.gif)

## Why

Coding agents run shell commands, query databases and call the internet on your behalf. Their
permission prompts understand *tools*, not *data*: `curl` is just `curl`, whether it fetches a tarball
or posts a patient list. In a GDPR, KVKK or HIPAA environment one such call is a reportable incident.

pii-gate reads the **content** of every call and says no when it has to. It was written for a team that
runs agents against clinical databases every day, and then rewritten from scratch, without a single
line of that environment in it, so that anyone can use it.

## Install

```
pip install pii-gate            # or: pipx install pii-gate
pii-gate install codex          # writes ~/.codex/hooks.json
pii-gate install claude         # writes ~/.claude/settings.json
pii-gate status
```

Codex only runs hooks you have trusted: start `codex`, type `/hooks`, review and trust the new entry.
Add `--project` to install into `./.codex` or `./.claude` of one repository instead of your home.

Requirements: Python 3.9 or newer. No dependencies.

## What it blocks

| rule              | default | what                                                                                   |
|-------------------|---------|----------------------------------------------------------------------------------------|
| `tckn`            | block   | Turkish national ID numbers (11 digits, both check digits verified)                     |
| `es-dni`          | block   | Spanish DNI and NIE (check letter verified)                                             |
| `it-cf`           | block   | Italian codice fiscale (check character and birth day verified, omocodia aware)         |
| `nl-bsn`          | block   | Dutch BSN (11-check), only next to a `BSN` or `burgerservicenummer` label               |
| `pl-pesel`        | block   | Polish PESEL (checksum and birth date), only next to a `PESEL` label                     |
| `se-personnummer` | block   | Swedish personnummer / samordningsnummer (Luhn and birth date), only next to a `personnummer` or `samordningsnummer` label |
| `iban`            | block   | IBANs (mod-97 checksum, per-country length)                                             |
| `card`            | block   | payment card numbers (Luhn, 13 to 19 digits, plausible prefix)                          |
| `secret`          | block   | private keys, AWS, OpenAI/Anthropic, GitHub, Slack, Google tokens, JWTs                 |
| `exfil`           | block   | uploads: `curl -d/-F/-T`, `wget --post-file`, `scp`, `rsync`, `aws s3 cp`, pipes into `nc`/`ssh`, `requests.post(...)`, and any outbound call whose command line already contains personal data |
| `git-push`        | block   | the agent never publishes; you push                                                     |
| `tamper`          | block   | writes to `.pii-gate.json`, the agents' hook settings, `--no-verify`, `PII_GATE_*=` overrides |
| `sql-pii`         | block   | SELECT lists with sensitive columns (national IDs, birth dates, card numbers, health, salary), or names and contact details when the query touches a person table |
| `sql-star`        | block   | `SELECT *` on a person table                                                            |
| `email`           | warn    | e-mail addresses (reserved domains such as `example.com` are ignored)                   |
| `phone`           | warn    | Turkish mobile and international phone numbers                                          |
| `secret-assign`   | warn    | `password = "..."` style assignments with a literal value                               |
| `sql-pii-context` | warn    | names and contact columns outside a person table (a supplier's phone is not personal data) |

`warn` findings are allowed and written to the decision log; `block` findings stop the call. Change any
rule's level in the config, including turning the SQL gate off if your project is not a data project.

What the agent sees when it is stopped:

```
pii-gate blocked this Bash call.
  - tckn: 1 match (Turkish national ID, checksum valid, e.g. "1***")
  - exfil: 1 match (curl with outbound call carrying sensitive data, e.g. "curl")
Personal data, secrets and outbound transfers must not leave this machine. Remove them.
If this is synthetic test data, the user can allow it in .pii-gate.json (allow_values, allow_paths);
the agent may not edit that file.
```

The value itself is never in the message, never in the log.

## Where it looks

| event                        | Codex CLI                                   | Claude Code                                              |
|------------------------------|---------------------------------------------|----------------------------------------------------------|
| shell command                | `Bash` (all rules)                          | `Bash`, `PowerShell` (all rules)                         |
| file write                   | `apply_patch`: added lines only             | `Edit`, `MultiEdit`, `Write`, `NotebookEdit`: new text only |
| web                          | hosted tools cannot be hooked by Codex      | `WebFetch`, `WebSearch`                                  |
| MCP tools                    | every string argument                       | every string argument                                    |
| your prompt                  | `UserPromptSubmit`                          | `UserPromptSubmit`                                       |

File writes honour `allow_paths`, so your synthetic test fixtures keep working.

## Configuration

Optional. Looked up in this order: `$PII_GATE_CONFIG`, `./.pii-gate.json` (the agent's working
directory), `~/.pii-gate.json`. The first file found wins.

```json
{
  "rules": { "email": "block", "git-push": "off", "sql-pii": "warn" },
  "allow_values": ["12345678950"],
  "allow_paths": ["tests/*", "fixtures/*"],
  "email_allow_domains": ["mycompany.example"],
  "sql": {
    "extra_pii_columns": ["protocol_no", "insurance_no"],
    "extra_person_tables": ["donor", "guardian"],
    "ignore_columns": ["name"]
  },
  "scan_prompts": true,
  "fail_open": false,
  "log": true
}
```

The agent cannot edit this file: every attempt is itself a `tamper` block.

## Command line

```
pii-gate check "text"              # what would happen to this text (exit 1 if blocked)
pii-gate check --command "cmd"     # same, with the shell rules (exfil, git-push, tamper)
pii-gate scan [paths]              # scan files; exit 1 on blocking findings
pii-gate scan --staged             # lines added in the git index, for a pre-commit hook
pii-gate install|uninstall codex|claude|all [--project]
pii-gate status
```

Pre-commit, in `.git/hooks/pre-commit`:

```sh
#!/bin/sh
exec pii-gate scan --staged
```

## Design principles

- **Fail closed.** Bad input, a crash in a detector, an unreadable config: the call is blocked, with a
  message that says why. A gate that fails open is not a gate. Set `fail_open` if you disagree.
- **Values never leave the process.** Findings carry the rule name and the first character. The deny
  message and the decision log (`~/.pii-gate/decisions.log`) contain counts, never data.
- **One engine, two agents.** Codex and Claude speak the same hook protocol (JSON in, exit code 2 to
  block, stderr as the reason). Everything is tested against both payload shapes.
- **The agent cannot disable its own gate.** Config files, hook settings and bypass flags are protected
  by the `tamper` rule.
- **Two-tier SQL.** National IDs are sensitive everywhere. A phone column is sensitive in `patients`,
  not in `suppliers`. Aggregations that reveal nothing (`COUNT`, `LEN`, `IS NULL`, first letter, year)
  pass.
- **Zero dependencies, pure Python.** Nothing to audit but this repository. The hook starts in tens of
  milliseconds.

## How it compares

- **Secret scanners** such as gitleaks, detect-secrets or trufflehog scan files and git history for
  credentials. pii-gate runs inside the agent loop, before the call, and also covers personal data,
  uploads and SQL.
- **PII libraries** such as Microsoft Presidio detect entities with NLP models inside an application you
  write. pii-gate needs no integration and no model: one hook, checksums, no dependencies.
- **The agents' own permission settings** decide which tools and command prefixes may run, and Codex's
  sandbox can cut network access entirely. pii-gate looks at what a call carries, so `curl` downloads
  keep working while `curl -d @patients.csv` does not.

They work well together: a secret scanner in CI, pii-gate where the agent runs.

## Limitations

- Detectors are pattern based. Checksums keep false positives low for IDs, IBANs and cards; phone and
  e-mail detection is heuristic and therefore `warn` by default.
- Only what the agent *sends* is inspected. What the agent *reads* (a file full of records) is not
  redacted; that is on the roadmap via `PostToolUse`.
- Codex does not expose its hosted web tools to hooks, so web calls are gated in Claude Code only.
- National IDs are validated with checksums for Turkey, Spain, Italy, the Netherlands, Poland and Sweden.
  Dutch BSN, Polish PESEL and Swedish personnummer checks are weak on their own, so those three are matched
  only next to their label. Other countries' identifiers are welcome as contributions, with synthetic test values.
- This is a guard rail, not a data-loss-prevention product. Use it together with least-privilege
  database accounts and the agents' own permission settings.

## Roadmap

- `PostToolUse` redaction of tool output (file reads, query results).
- National identifiers of more countries, each with its checksum.
- A `--report` mode that summarises the decision log.
- Gemini CLI support once its hook protocol settles.

## Contributing

Issues and pull requests are welcome. Every detector change needs a test with **synthetic** values
(see `tests/_synthetic.py`, which generates valid check digits from arbitrary digits). Never commit
real personal data, not even "just one example". `pii-gate scan .` runs in CI on this repository too.

## License

MIT. See [LICENSE](LICENSE).

Türkçe özet için [README.tr.md](README.tr.md).
