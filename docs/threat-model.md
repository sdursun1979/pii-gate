# Threat model

pii-gate is a guard rail, not a sandbox and not a data-loss-prevention product. This page says
exactly what it defends against, what it does not, and which known gaps remain. Please read it before
relying on the gate for anything regulated.

## What is being protected

Personal data and secrets that live on the developer's machine or in databases that machine can
reach: national identity numbers, bank account numbers, payment card numbers, API keys and private
keys, and the columns of person tables. The adversary is not a malicious human. It is an AI coding
agent (Codex CLI, Claude Code, Gemini CLI) that, through a mistake, an over-eager plan or a prompt
injection in a file it read, is about to move that data somewhere it should not go.

## Where the gate sits

The agents call a hook *before* they run a tool and *before* they send a prompt. pii-gate is that
hook. It sees the arguments of the call (the shell command, the file content to be written, the path
to be read, the MCP tool arguments, the prompt) and answers "go ahead" (exit 0) or "no, and here is
why" (exit 2). The data itself never leaves the hook process: the message and the log contain rule
names, counts and a masked first character.

| the agent is about to...                        | what pii-gate inspects                                    |
|-------------------------------------------------|-----------------------------------------------------------|
| run a shell command                             | the command: personal data in it, upload commands, `git push`, attempts to disable the gate |
| write or edit a local file                      | the new text (not what already exists in the file)        |
| read a local file (`Read`, `read_file`)         | the file's content; block-level personal data or secrets inside it stop the read |
| publish a local file (`Artifact`, `SendUserFile`) | the file's content                                       |
| call the web (`WebFetch`, `WebSearch`)           | the URL and the query                                     |
| call an MCP tool                                | every string, number and key in the arguments; `command`/`cmd` arguments get the shell rules |
| send a prompt                                   | the prompt text                                           |

## What it does not do

1. **It does not see what the model already knows.** Everything the agent reads successfully, every
   tool result, and every prompt that passes is sent to the model provider's API. The read gate
   stops the agent from opening files that contain checksum-valid identifiers or secrets, but
   `cat file` in a shell, a `Grep` result, a database query result returned by an MCP server, or a
   file attached with `@` in Claude Code are not inspected before they reach the model. Control that
   side with least-privilege database accounts, masked views and the agents' own permission settings.
2. **It is pattern based.** It finds identifiers with a checksum (TR, ES, IT, NL, PL), IBANs, cards,
   known secret formats and heuristic e-mail and phone numbers. It does not find a name, an address or
   a diagnosis written in free text. The SQL rules match column and table names; a view with renamed
   columns passes.
3. **It is not a sandbox.** A determined agent can write a script that uploads a file and then run
   it with `python upload.py`; the gate sees only `python upload.py`. It can encode data before an
   outbound call in ways the rules do not recognise. The exfiltration rules cover the common tools and
   flags, obfuscation with quotes, backslashes and `${IFS}`, and any outbound call that is fed from a
   file or a sub-command, but the list is finite. Pair pii-gate with network controls (Codex's
   sandbox, Claude Code's sandbox, an egress proxy) when the data is sensitive.
4. **Fail-closed covers failures inside pii-gate, plus what the agent lets us control.** A detector
   crash, bad JSON, an unreadable or untrusted config, an oversized payload: blocked. A hook that
   cannot start or times out is handled by the agent, not by pii-gate:
   - Claude Code: the installer writes `onFailure: "block"` (Claude Code 2.1.295 or later), so a
     missing interpreter or a timeout blocks the call. Older versions let the call through.
   - Codex CLI: the installed command is wrapped so that a missing interpreter still exits 2. A
     timeout is treated by Codex as a non-blocking failure; there is no setting to change that.
   - Gemini CLI: a non-zero exit other than 2 and a timeout are warnings; the call proceeds.
   Payloads above 8 MB are blocked without scanning, so a scan cannot run into the 20 s timeout.
5. **The user can switch it off; the agent cannot.** The `tamper` rule stops the agent from editing
   the gate's config, the agents' hook settings, Python start-up files, and from uninstalling or
   downgrading the package. It does not stop you. It also cannot stop an instruction in `CLAUDE.md`,
   `AGENTS.md` or a prompt that tells the agent to work around the gate; the gate then sees and judges
   whatever the agent tries next.
6. **Allow-listed paths are not scanned.** `allow_paths` exempts writes to and reads of matching
   files inside the project. Keep the patterns narrow (`tests/fixtures/*`, not `*`).
7. **Blocked prompts stay in local history.** The agents keep prompt history and transcripts on disk.
   pii-gate asks Claude Code not to echo the blocked prompt back (`suppressOriginalPrompt`), but it
   cannot delete what the agent has already stored.
8. **Only local sessions.** Claude Code cloud sessions and Codex cloud tasks do not read your local
   hook settings, so the gate is not present there.

## Configuration trust

A project's `.pii-gate.json` travels with the repository, and the agent may have cloned that
repository a minute ago. A project file may therefore only tighten the gate: raise a rule's level,
add allow-listed values, allow paths inside the project, add sensitive columns and person tables.
Lowering a level, `fail_open`, `scan_prompts`, `log`, absolute or `..` allow-path patterns are
accepted only from `~/.pii-gate.json` or the file named by `PII_GATE_CONFIG`, or from a project file
when the home file says `"trust_project_config": true`. A project file that tries to loosen the gate
is a config error, and a config error blocks every call until it is fixed.

The project file is looked up at the project root (`CLAUDE_PROJECT_DIR` / `GEMINI_PROJECT_DIR`, else
the nearest ancestor of the working directory with a `.pii-gate.json` or `.git`), not in whatever
subdirectory the agent has changed into.

## How the gate protects itself

- The hook runs through the installed `pii-gate` console script, so a `pii_gate/` folder or a
  `json.py` written into the project is never imported instead of the real code. Where no console
  script is found, the interpreter is started with the working directory removed from `sys.path`.
- Writes to `.pii-gate.json`, the agents' hook and settings files, `pii_gate/` or `pii_gate.py` at the
  project root, `sitecustomize.py`, `usercustomize.py` and `.pth` files in site-packages are `tamper`
  findings, through any tool.
- Shell commands that mention those files are blocked unless they are a single read-only command
  (`cat`, `jq`, `git diff`, ...). Destructive commands on `.claude`, `.codex`, `.gemini` and
  `.pii-gate` directories are blocked. `pii-gate uninstall`, `pip install/uninstall ... pii-gate`,
  `PII_GATE_*` assignments, `--no-verify`, `core.hooksPath`, `hooks=false`, `disableAllHooks`,
  `claude --bare` are blocked.
- Findings never carry the matched value: the first character and `***`, or a rule name and a count.
  The decision log holds counts only.

## Known gaps

These are known and either out of scope or not yet addressed. Reports of new ones are welcome,
privately, through [SECURITY.md](../SECURITY.md).

- Data an agent reads through a shell (`cat`, `sed`, `sqlcmd`), through `Grep`, through an MCP
  query result or through an `@` mention reaches the model unseen.
- A script written to disk and then executed, a binary that uploads, or an encoding the rules do not
  know (base64 inside a URL path, for example) can carry data out.
- Free-text personal data (names, addresses, diagnoses) is not detected.
- Phone and e-mail detection is heuristic and therefore `warn` by default; `warn` is logged, not
  shown to the agent.
- Timeouts are fail-open in Codex CLI and Gemini CLI.
- Files larger than 5 MB and binary files (PDF, images, office documents) are not inspected by the
  read gate.
- A `.pii-gate.json` placed in a repository the user trusts (`trust_project_config: true`) is as
  powerful as the home file.
