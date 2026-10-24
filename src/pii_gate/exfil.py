"""Exfiltration and tamper rules for shell commands and file paths.

Commands are matched after light de-obfuscation (quotes inside words, backslashes before
letters, ${IFS}), because the shell removes those before it runs the command and the gate
must see what the shell sees.
"""
from __future__ import annotations

import posixpath
import re
from typing import Iterator, Optional

from .detectors import Finding

# --------------------------------------------------------------------------- normalisation
_WORD_QUOTES = re.compile(r"""(["'])([A-Za-z0-9_@./:=+-]*)\1""")   # 'curl', cu""rl, cur'l', -d'@f'
_DOLLAR_QUOTE = re.compile(r"\$'([^']*)'")
_IFS = re.compile(r"\$\{IFS\}|\$IFS\b")
_BACKSLASH_LETTER = re.compile(r"\\([A-Za-z])")


def normalize(command: str) -> str:
    """What the shell will execute, roughly: strip word-internal quoting tricks."""
    s = _DOLLAR_QUOTE.sub(r"\1", command)
    s = _WORD_QUOTES.sub(r"\2", s)
    s = _IFS.sub(" ", s)
    s = _BACKSLASH_LETTER.sub(r"\1", s)
    return s


# --------------------------------------------------------------------------- git push
_GIT_PUSH = re.compile(
    r"\bgit(?:\.exe)?\b(?:\s+-[Cc]\s+\S+|\s+--?[\w-]+(?:=\S+)?)*\s+(?:push|svn\s+dcommit|send-email)\b"
    r"|\bhub\s+push\b", re.I)

# --------------------------------------------------------------------------- outbound
_OUTBOUND = re.compile(
    r"(?<![\w.-])(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)(?:\.exe)?\b", re.I)
# curl/wget/PowerShell flags that send a body or a file. Short-flag bundles (-sd, -Ld) count;
# that part is case sensitive because -f, -s, -D mean other things.
_UPLOAD_FLAG = re.compile(
    r"(?:^|\s)(?:(?-i:-[A-Za-z]{0,3}[dF][A-Za-z]{0,2}|-T(?!\s*\d))"
    r"|--data(?:-binary|-raw|-urlencode|-ascii)?|--form(?:-string)?|--upload-file|--json|--config|-K"
    r"|--post-data|--post-file|--body-data|--body-file|--method[= ]?(?:POST|PUT|PATCH)"
    r"|-X\s*(?:POST|PUT|PATCH)|--request[= ]?(?:POST|PUT|PATCH)"
    r"|-InF\w*|-Bo\w*|-Me\w*\s+(?:Post|Put|Patch))(?=\s|=|@|$)", re.I)
# Anything fed to an outbound command from a file or a sub-command carries data we cannot see.
_OUTBOUND_INPUT = re.compile(
    r"(?<![\w.-])(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|ssh|nc|ncat|netcat|socat"
    r"|openssl|telnet|nslookup|dig|ping|xdg-open|Start-Process)(?:\.exe)?\b[^|&;]*(?:<|\$\(|`)", re.I)
_ALWAYS_UPLOAD = re.compile(
    r"(?<![\w.-])(?:scp|sftp|rsync|rclone|Start-BitsTransfer|ftp|lftp|tftp|smbclient|ncftpput|s3cmd"
    r"|mail|mailx|sendmail|msmtp|mutt|swaks|Send-MailMessage|clip|pbcopy|xclip|xsel|wl-copy|Set-Clipboard"
    r"|ngrok|cloudflared|localtunnel)(?:\.exe)?(?![\w.@-])"
    r"|\baws\s+s3\s+(?:cp|sync|mv)\b|\baws\s+s3api\s+put-object(?![\w-])|\bgsutil\s+(?:cp|rsync|mv)\b"
    r"|\bazcopy(?:\.exe)?\s+(?:copy|cp|sync)\b"
    r"|\bgcloud\s+storage\s+(?:cp|rsync|mv)\b|\baz\s+storage\s+(?:blob|file)\s+upload"
    r"|\bmc\s+(?:cp|mirror|put)\b|\bb2\s+(?:upload-file|file\s+upload)\b"
    r"|\bgh\s+(?:gist\s+create|release\s+(?:create|upload)|(?:issue|pr)\s+create\b[^|&;]*--body-file"
    r"|api\b[^|&;]*(?:-X\s*(?:POST|PUT|PATCH)|--method\s*(?:POST|PUT|PATCH)|\s-[fF]\s|--input))"
    r"|\bglab\s+(?:snippet\s+create|release\s+(?:create|upload))\b"
    r"|\b(?:npm|yarn|pnpm)\s+publish\b|\btwine\s+upload\b|\bdocker\s+push\b|\bkubectl\s+cp\b"
    r"|\bpython[23]?\s+-m\s+http\.server\b|\bssh\b[^|&;]*\s-R\s|/dev/(?:tcp|udp)/"
    r"|\|\s*(?:nc|ncat|netcat|socat|ssh)\b", re.I)
_CODE_HTTP = re.compile(
    r"requests\.(?:post|put|patch)\s*\(|urllib\.request\.urlopen\s*\([^)]*\bdata\s*="
    r"|http\.client\.HTTPS?Connection|fetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|PATCH)"
    r"|Net\.WebClient|\bUpload(?:String|File|Data|Values)\b|\b(?:Post|Put|Patch|Send)Async\b"
    r"|HttpClient|smtplib|\bsendmail\s*\(", re.I)

# --------------------------------------------------------------------------- tamper
# Files that configure the gate or the agents' hooks, and the Python start-up files an agent
# could use to shadow the gate's own module.
_GATE_FILES = re.compile(
    r"\.pii-gate(?:\.json)?(?![\w-])"
    r"|\.codex[\\/]+(?:hooks\.json|config\.toml)"
    r"|\.claude[\\/]+settings(?:\.local)?\.json|\.claude\.json(?![\w-])|managed-settings(?:\.json|\.d\b)"
    r"|\.gemini[\\/]+settings\.json"
    r"|(?<![\w-])(?<!\w/)(?<!\w\\)pii_gate(?:[\\/]|\.py\b)"
    r"|(?:site|user)customize\.py|(?:site|dist)-packages[\/][^\s\"']*\.pth\b", re.I)
_GATE_DIRS = re.compile(r"(?<![\w-])\.(?:codex|claude|gemini|pii-gate)(?=[\s\"'/\\]|$)", re.I)
_DESTRUCTIVE = re.compile(
    r"\b(?:rm|rmdir|rd|del|erase|mv|move|ren|rename|chmod|chown|chattr|attrib|icacls|takeown"
    r"|Remove-Item|Move-Item|Rename-Item|Set-Acl)\b", re.I)
# A single read-only command (no pipes, chains, redirects or substitutions) may mention a gate file.
_READ_ONLY = re.compile(
    r"^\s*(?:cat|type|less|more|head|tail|bat|grep|rg|findstr|ls|dir|stat|wc|diff|jq|file|md5sum|sha256sum"
    r"|Get-Content|gc|Select-String|Get-Item|Get-ChildItem|Get-FileHash|Test-Path|Format-Hex"
    r"|pii-gate|python[23]?\s+-m\s+pii_gate|git\s+(?:diff|status|log|show|blame))\b[^|;&<>`$]*$", re.I)
_BYPASS = re.compile(
    r"PII_GATE_\w+[\"'\]]*\s*[=:]|--dangerously-bypass-hook-trust|\b(?:codex_)?hooks\s*=\s*false"
    r"|disableAllHooks|allow_managed_hooks_only|--no-verify|core\.hooksPath|\bclaude\b[^|&;]*--bare\b"
    r"|\bpii[-_]gate\s+uninstall\b|\b(?:pip[23]?|pipx|uv(?:\s+pip)?|uv\s+tool)\s+(?:uninstall|install|remove)\b[^|&;]*pii[-_]gate"
    r"|/hooks\s+disable", re.I)
_STARTUP_FILES = ("sitecustomize.py", "usercustomize.py")


def find_git_push(command: str) -> Iterator[Finding]:
    for m in _GIT_PUSH.finditer(normalize(command)):
        yield Finding("git-push", m.start(), m.end(), "git push", "the agent must not publish; you push")


def find_exfil(command: str, has_sensitive: bool) -> Iterator[Finding]:
    """Outbound transfer. Downloads are fine; uploads, or any outbound call that carries data, are not."""
    command = normalize(command)
    m = _ALWAYS_UPLOAD.search(command)
    if m:
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), "file transfer command")
        return
    m = _CODE_HTTP.search(command)
    if m:
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), "HTTP upload in code")
        return
    m = _OUTBOUND_INPUT.search(command)
    if m:
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()),
                      "outbound call fed from a file or a sub-command")
        return
    m = _OUTBOUND.search(command)
    if m and (has_sensitive or _UPLOAD_FLAG.search(command)):
        why = "outbound call carrying sensitive data" if has_sensitive else "upload flag"
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), f"{m.group().strip()} with {why}")


def find_tamper(command: str) -> Iterator[Finding]:
    command = normalize(command)
    m = _BYPASS.search(command)
    if m:
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()), "attempt to bypass or remove the gate")
        return
    m = _GATE_FILES.search(command)
    if m and not _READ_ONLY.match(command):
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()),
                      "command touches the gate's own configuration")
        return
    m = _GATE_DIRS.search(command)
    if m and _DESTRUCTIVE.search(command):
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()),
                      "destructive command on an agent configuration directory")


def tamper_path(path: str, cwd: Optional[str] = None) -> bool:
    """True if a file path belongs to the gate, the agents' hook configuration, or a Python
    start-up location from which a module in the working directory could shadow the gate."""
    norm = posixpath.normpath(path.replace("\\", "/"))
    low = norm.lower()
    base = posixpath.basename(low)
    if base == ".pii-gate.json" or "/.pii-gate/" in low or base in _STARTUP_FILES:
        return True
    if base.endswith(".pth") and re.search(r"(?:site|dist)-packages/", low):
        return True
    if re.search(r"\.codex/+(?:hooks\.json|config\.toml)$|\.claude/+settings(?:\.local)?\.json$"
                 r"|/\.claude\.json$|managed-settings(?:\.json|\.d/)|\.gemini/+settings\.json$", norm, re.I):
        return True
    rel = norm
    if cwd:
        root = cwd.replace("\\", "/").rstrip("/") + "/"
        if norm.startswith(root):
            rel = norm[len(root):]
    rel = posixpath.normpath(rel)
    first = rel.split("/", 1)[0]
    return first in ("pii_gate", "pii_gate.py")


def mask_cmd(token: str) -> str:
    token = token.strip()
    return token[:12] if len(token) <= 12 else token[:12] + "..."
