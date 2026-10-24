"""Pattern detectors for personal data and secrets.

Every detector yields Finding objects. A Finding never carries the matched value,
only a masked sample (first character + "***"), so findings are safe to log and
safe to show to the agent.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, replace
from datetime import date
from typing import Iterable, Iterator, List


@dataclass(frozen=True)
class Finding:
    rule: str
    start: int
    end: int
    sample: str
    note: str = ""


def mask(value: str) -> str:
    value = value.strip()
    return (value[0] + "***") if value else "***"


# Values published as test data in countless docs and SDKs. They identify nobody.
WELL_KNOWN_TEST_VALUES = frozenset({
    "10000000146",                       # the canonical TCKN test number
    "4111111111111111", "4242424242424242", "5555555555554444",
    "378282246310005", "6011111111111117", "4000000000000002",
    "TR330006100519786457841326",        # example IBANs from the IBAN registry docs
    "GB82WEST12345698765432", "DE89370400440532013000",
    "12345678Z", "X1234567L",            # widely published Spanish DNI/NIE examples
    "RSSMRA85T10A562S",                  # the widely published codice fiscale example
    "123456782", "111222333",            # widely published Dutch BSN examples
    "44051401359",                       # the widely published PESEL example
})

# RFC 2606 / RFC 6761 reserved names plus GitHub's no-reply relay.
RESERVED_EMAIL_SUFFIXES = (
    "@example.com", "@example.net", "@example.org", ".example.com", ".example.net",
    ".example.org", ".example", ".invalid", ".localhost", ".test",
    "@users.noreply.github.com",
)

# --------------------------------------------------------------------------- normalisation
# Characters that render as nothing (zero-width space/joiners, word joiner, BOM, soft hyphen) are
# dropped so they cannot split a number; no-break and thin spaces become spaces; fullwidth digits and
# Latin letters become ASCII. find_pii and find_secrets report offsets in the original text.
_NORMALISE = dict.fromkeys("\u200b\u200c\u200d\u2060\ufeff\u00ad", "")
_NORMALISE.update(dict.fromkeys("\u00a0\u2007\u2009\u202f", " "))
_NORMALISE["\u2011"] = "-"                                                    # non-breaking hyphen
_NORMALISE.update({chr(0xFF10 + i): chr(0x30 + i) for i in range(10)})        # fullwidth 0-9
_NORMALISE.update({chr(0xFF21 + i): chr(0x41 + i) for i in range(26)})        # fullwidth A-Z
_NORMALISE.update({chr(0xFF41 + i): chr(0x61 + i) for i in range(26)})        # fullwidth a-z
# A regex finds the few characters to replace; str.translate walks every character of non-ASCII text
# through a dict and is twenty times slower on a large file.
_NORMALISE_RE = re.compile("[" + "".join(sorted(_NORMALISE)) + "]")
_DROPPED_RE = re.compile("[" + "".join(ch for ch, rep in _NORMALISE.items() if not rep) + "]")


def normalise(text: str) -> str:
    if text.isascii():
        return text
    return _NORMALISE_RE.sub(lambda m: _NORMALISE[m.group()], text)


def _dropped_positions(text: str) -> List[int]:
    """For each character normalise() drops, its index in the normalised text."""
    if text.isascii():
        return []
    return [m.start() - i for i, m in enumerate(_DROPPED_RE.finditer(text))]


def _original_offsets(findings: Iterable[Finding], dropped: List[int]) -> Iterator[Finding]:
    """Findings made on normalised text, with offsets moved back onto the original text."""
    if not dropped:
        yield from findings
        return
    for f in findings:
        yield replace(f, start=f.start + bisect.bisect_right(dropped, f.start),
                      end=f.end + bisect.bisect_left(dropped, f.end))


# --------------------------------------------------------------------------- TCKN
_TCKN = re.compile(r"\d(?<!\d\d)\d{10}(?!\d)")
# Written in groups: 123 456 789 01 or 123.456.789.01, one separator throughout. Phone numbers do not
# take this shape (Turkish ones are 10 digits, or 11 with a leading 0, grouped 3-3-2-2 / 4-3-2-2).
_TCKN_GROUPED = re.compile(r"[1-9](?<![\w+.,-][1-9])(?<!\d[ .][1-9])\d\d([ .])\d{3}\1\d{3}\1\d\d(?![\w-])(?![ .,]\d)")


def tckn_valid(s: str) -> bool:
    """Turkish national identity number: 11 digits, two check digits."""
    if len(s) != 11 or not s.isdigit() or s[0] == "0":
        return False
    d = [int(c) for c in s]
    odd = d[0] + d[2] + d[4] + d[6] + d[8]
    even = d[1] + d[3] + d[5] + d[7]
    if (odd * 7 - even) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def find_tckn(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _TCKN.finditer(text):
        s = m.group()
        if s in WELL_KNOWN_TEST_VALUES or s in allow or not tckn_valid(s):
            continue
        yield Finding("tckn", m.start(), m.end(), mask(s), "Turkish national ID, checksum valid")
    for m in _TCKN_GROUPED.finditer(text):
        s = m.group().replace(m.group(1), "")
        if s in WELL_KNOWN_TEST_VALUES or s in allow or m.group() in allow or not tckn_valid(s):
            continue
        yield Finding("tckn", m.start(), m.end(), mask(s), "Turkish national ID (grouped), checksum valid")


# --------------------------------------------------------------------------- other national IDs
_DNI = re.compile(
    r"(?P<num>\d(?<![A-Za-z0-9]\d)\d{7}|[XYZ](?<![A-Za-z0-9][XYZ])[- ]?\d{7})[- ]?(?P<letter>[A-Z])(?![A-Za-z0-9])"
)
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_id_valid(num: str, letter: str) -> bool:
    """Spanish DNI (8 digits) or NIE (X/Y/Z + 7 digits): the letter is the number mod 23."""
    digits = str("XYZ".index(num[0])) + num[1:] if num[0] in "XYZ" else num
    if len(set(digits)) == 1:
        return False
    return _DNI_LETTERS[int(digits) % 23] == letter


def find_es_id(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _DNI.finditer(text):
        num = m.group("num").replace("-", "").replace(" ", "")
        compact = num + m.group("letter")
        if compact in WELL_KNOWN_TEST_VALUES or compact in allow or m.group() in allow:
            continue
        if es_id_valid(num, m.group("letter")):
            yield Finding("es-dni", m.start(), m.end(), mask(compact), "Spanish DNI/NIE, check letter valid")


_CF_DIGIT = "[0-9LMNPQRSTUV]"   # omocodia: digits may be replaced by these letters
_CF = re.compile(
    rf"[A-Z](?<![A-Za-z0-9][A-Z])[A-Z]{{5}}{_CF_DIGIT}{{2}}[ABCDEHLMPRST]{_CF_DIGIT}{{2}}"
    rf"[A-Z]{_CF_DIGIT}{{3}}[A-Z](?![A-Za-z0-9])"
)
_CF_ODD = dict(zip("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", (
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
    2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23)))
_CF_OMOCODIA = {ch: str(i) for i, ch in enumerate("LMNPQRSTUV")}


def it_cf_valid(s: str) -> bool:
    """Italian codice fiscale: check character over 15 characters, plausible birth day (women +40)."""
    if len(s) != 16:
        return False
    total = 0
    for i, ch in enumerate(s[:15]):
        total += _CF_ODD[ch] if i % 2 == 0 else (int(ch) if ch.isdigit() else ord(ch) - 65)
    if chr(65 + total % 26) != s[15]:
        return False
    day = int("".join(_CF_OMOCODIA.get(ch, ch) for ch in s[9:11]))
    return 1 <= day <= 31 or 41 <= day <= 71


def find_it_cf(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _CF.finditer(text):
        s = m.group()
        if s in WELL_KNOWN_TEST_VALUES or s in allow or not it_cf_valid(s):
            continue
        yield Finding("it-cf", m.start(), m.end(), mask(s), "Italian codice fiscale, check character valid")


# Nine and eleven digit numbers are everywhere (orders, phones), and the BSN, PESEL and personnummer checks are
# weak enough that a random number passes often. These three are matched only next to their label.
_LABEL_WINDOW = 40
_BSN = re.compile(r"\d(?<!\d\d)\d{8}(?!\d)")
_BSN_LABEL = re.compile(r"(?i)\b(?:bsn|burgerservicenummer|sofi(?:nummer)?)\b")
_PESEL = re.compile(r"\d(?<!\d\d)\d{10}(?!\d)")
_PESEL_LABEL = re.compile(r"(?i)\bpesel\b")
_SE_PNR = re.compile(r"(?<!\d)(\d{6})([-+]?)(\d{4})(?!\d)")
_SE_PNR_LABEL = re.compile(r"(?i)\b(?:personnummer|samordningsnummer)\b")


def _labelled(label: "re.Pattern[str]", text: str, start: int) -> bool:
    return bool(label.search(text[max(0, start - _LABEL_WINDOW):start]))


def nl_bsn_valid(s: str) -> bool:
    """Dutch citizen service number: 9 digits, 11-check (weights 9..2, last digit -1)."""
    if len(s) != 9 or not s.isdigit() or len(set(s)) == 1:
        return False
    total = sum(int(c) * w for c, w in zip(s[:8], range(9, 1, -1))) - int(s[8])
    return total % 11 == 0


def find_nl_bsn(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _BSN.finditer(text):
        s = m.group()
        if s in WELL_KNOWN_TEST_VALUES or s in allow or not nl_bsn_valid(s):
            continue
        if _labelled(_BSN_LABEL, text, m.start()):
            yield Finding("nl-bsn", m.start(), m.end(), mask(s), "Dutch BSN next to its label, 11-check valid")


def pl_pesel_valid(s: str) -> bool:
    """Polish PESEL: 11 digits, weighted checksum, birth date with the century encoded in the month."""
    if len(s) != 11 or not s.isdigit():
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    if (10 - sum(int(c) * w for c, w in zip(s, weights)) % 10) % 10 != int(s[10]):
        return False
    yy, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
    century = {0: 1900, 1: 2000, 2: 2100, 3: 2200, 4: 1800}.get(mm // 20)
    try:
        date(century + yy, mm % 20, dd)
    except (TypeError, ValueError):
        return False
    return True


def find_pl_pesel(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _PESEL.finditer(text):
        s = m.group()
        if s in WELL_KNOWN_TEST_VALUES or s in allow or not pl_pesel_valid(s):
            continue
        if _labelled(_PESEL_LABEL, text, m.start()):
            yield Finding("pl-pesel", m.start(), m.end(), mask(s), "Polish PESEL next to its label, checksum valid")


def se_personnummer_valid(s: str, sep: str = "-") -> bool:
    """Swedish personnummer / samordningsnummer: YYMMDD, separator, NNNC, Luhn over the nine digits before C.

    A coordination number adds 60 to the day. The two-digit year leaves the century open: "-" means the
    person is under 100 (this or the previous century), "+" means 100 or older (previous centuries).
    """
    if len(s) != 10 or not s.isdigit() or sep not in ("", "-", "+") or len(set(s)) == 1:
        return False
    if not luhn_valid(s):
        return False
    yy, mm, dd = int(s[0:2]), int(s[2:4]), int(s[4:6])
    if dd > 60:
        dd -= 60
    centuries = (1800, 1900) if sep == "+" else (1900, 2000)
    for century in centuries:
        try:
            date(century + yy, mm, dd)
            return True
        except ValueError:
            continue
    return False


def find_se_personnummer(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _SE_PNR.finditer(text):
        s = m.group(1) + m.group(3)
        if m.group() in allow or s in allow or not se_personnummer_valid(s, m.group(2)):
            continue
        if _labelled(_SE_PNR_LABEL, text, m.start()):
            yield Finding("se-personnummer", m.start(), m.end(), mask(m.group()),
                          "Swedish personnummer next to its label, Luhn and date valid")


# --------------------------------------------------------------------------- IBAN
# Case-insensitive, groups separated by a space or a hyphen, optionally glued to the word "IBAN".
_IBAN = re.compile(
    r"(?<![A-Za-z0-9])(?:[Ii][Bb][Aa][Nn])?(?P<iban>[A-Za-z]{2}\d{2}(?:[ -]?[A-Za-z0-9]){11,30})(?![A-Za-z0-9])"
)
# SWIFT IBAN registry: country code -> IBAN length. A code not listed here is not an IBAN country.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27,
    "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
    "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
    "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18,
    "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}


def iban_valid(compact: str) -> bool:
    cc = compact[:2]
    if IBAN_LENGTHS.get(cc) != len(compact) or not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


def find_iban(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    pos = 0
    while True:
        m = _IBAN.search(text, pos)
        if not m:
            return
        pos = m.end()
        raw = m.group("iban")
        compact = re.sub(r"[ -]", "", raw).upper()
        n = IBAN_LENGTHS.get(compact[:2])
        if not n or len(compact) < n:
            continue
        if len(compact) > n:
            # The greedy match ran into what follows (" TL", " 2024", the next IBAN). Keep the
            # country's length, but only when it ends at a group boundary of the original text.
            end = _raw_end(raw, n)
            if end >= len(raw) or raw[end] not in " -":
                continue
            compact = compact[:n]
            pos = m.start("iban") + end
        if compact in WELL_KNOWN_TEST_VALUES or compact in allow or m.group() in allow or not iban_valid(compact):
            continue
        yield Finding("iban", m.start(), pos, mask(compact), f"IBAN ({compact[:2]}), checksum valid")


def _raw_end(raw: str, n: int) -> int:
    """Index in raw just after its n-th character that is not a separator."""
    count = 0
    for i, ch in enumerate(raw):
        if ch not in " -":
            count += 1
            if count == n:
                return i + 1
    return len(raw)


# --------------------------------------------------------------------------- cards
_CARD = re.compile(r"\d(?<!\d\d)(?:[ .-]?\d){12,18}(?!\d)")
_CARD_SEP = re.compile(r"[ .-]")


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_prefix_ok(digits: str) -> bool:
    """Issuer ranges: 3 (Amex, Diners, JCB), 4 (Visa), 5 (Mastercard, Maestro), 6 (Discover, UnionPay,
    Maestro), Mastercard 2221-2720, MIR 2200-2204, Troy 9792."""
    first, four = digits[0], digits[:4]
    if first in "3456":
        return True
    if first == "2":
        return "2200" <= four <= "2204" or "2221" <= four <= "2720"
    return four == "9792"


def _card_candidates(raw: str) -> Iterator[int]:
    """Digit counts to try: the whole run, then shorter runs that end at a group boundary, so that a
    trailing expiry date or CVV ("4539 ... 1486 12/26", "...1486 123") does not hide the number.
    Shorter runs are only taken from groups of three or more digits (cards are printed in 4s, Amex
    4-6-5), never from a string of single digits."""
    groups = [len(g) for g in _CARD_SEP.split(raw) if g]
    total = sum(groups)
    yield total
    run = 0
    cuts = []
    for g in groups[:-1]:
        if g < 3:
            break
        run += g
        if 13 <= run <= 19:
            cuts.append(run)
    yield from reversed(cuts)


def find_card(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    pos = 0
    while True:
        m = _CARD.search(text, pos)
        if not m:
            return
        pos = m.end()
        raw = m.group()
        digits = _CARD_SEP.sub("", raw)
        if not _card_prefix_ok(digits):
            continue
        for n in _card_candidates(raw):
            cand = digits[:n]
            if not 13 <= n <= 19 or len(set(cand)) == 1 or not luhn_valid(cand):
                continue
            if n < len(digits):
                pos = m.start() + _raw_end_digits(raw, n)
            if cand not in WELL_KNOWN_TEST_VALUES and cand not in allow:
                yield Finding("card", m.start(), pos, mask(cand), "payment card number, Luhn valid")
            break


def _raw_end_digits(raw: str, n: int) -> int:
    count = 0
    for i, ch in enumerate(raw):
        if ch.isdigit():
            count += 1
            if count == n:
                return i + 1
    return len(raw)


# --------------------------------------------------------------------------- e-mail
# A trailing dot is allowed when it ends the sentence (not followed by more domain characters).
_EMAIL = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-])(?!\.[\w-])"
)


def find_email(text: str, allow: Iterable[str] = (), allow_domains: Iterable[str] = ()) -> Iterator[Finding]:
    domains = tuple("@" + d.lower().lstrip("@") for d in allow_domains)
    for m in _EMAIL.finditer(text):
        value = m.group()
        low = value.lower()
        if value in allow or low.endswith(RESERVED_EMAIL_SUFFIXES) or (domains and low.endswith(domains)):
            continue
        # git@host:org/repo and scp-style user@host:/path are SSH addresses, not mailboxes.
        if low.startswith("git@") or (text.startswith(":", m.end()) and text[m.end() + 1:m.end() + 2].strip()):
            continue
        yield Finding("email", m.start(), m.end(), mask(value), "e-mail address")


# --------------------------------------------------------------------------- phone
_PHONE = re.compile(
    r"(?<![\w+.-])(?:"
    r"(?:\+\d{1,3}[\s.-]?)?\(?0?5\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}"   # Turkish mobile
    r"|\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}"                     # international
    r")(?![\w-])"
)


def find_phone(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _PHONE.finditer(text):
        value = m.group()
        digits = re.sub(r"\D", "", value)
        if len(digits) < 10 or value in allow or digits in allow:
            continue
        yield Finding("phone", m.start(), m.end(), mask(digits), "phone number")


# --------------------------------------------------------------------------- secrets
# Most patterns start with their literal prefix and check the preceding character with a fixed-width
# lookbehind placed after it: the regex engine can then jump between occurrences of the prefix
# instead of trying every position, which keeps the scan of a large file cheap.
# (label, pattern, case-insensitive, skip documentation placeholders). Case-insensitive patterns are
# written in lower case and run over the lower-cased text. The "value" group, when present, is what
# the placeholder test looks at.
_SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----"), False, False),
    ("AWS access key", re.compile(r"A(?:KIA|SIA)(?<![A-Z0-9]A...)[0-9A-Z]{16}(?![A-Z0-9])"), False, True),
    ("AWS secret key", re.compile(
        r"aws[_-]?secret[_-]?access[_-]?key[\"']?[ \t]{0,5}[:=][ \t]{0,5}[\"']?(?P<value>[a-z0-9/+]{40})(?![a-z0-9/+=])"),
     True, True),
    ("OpenAI/Anthropic-style key", re.compile(
        r"sk-(?<![\w-]sk-)(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"), False, True),
    ("Stripe key", re.compile(r"[sr]k_(?:live|test)_(?<![\w-].{8})[A-Za-z0-9]{16,}"), False, True),
    ("GitHub token", re.compile(r"g(?<!\wg)(?:h[pousr]_[A-Za-z0-9]{36,}|ithub_pat_[A-Za-z0-9_]{22,})"), False, True),
    ("GitLab token", re.compile(r"glpat-(?<![\w-]glpat-)[A-Za-z0-9_-]{20,}"), False, True),
    ("npm token", re.compile(r"npm_(?<![\w-]npm_)[A-Za-z0-9]{36,}"), False, True),
    ("PyPI token", re.compile(r"pypi-AgE(?:IcHlwaS5vcmc|NdGVzdC5weXBpLm9yZw)[A-Za-z0-9_-]{50,}"), False, True),
    ("Hugging Face token", re.compile(r"hf_(?<![\w-]hf_)[A-Za-z0-9]{30,}"), False, True),
    ("Slack token", re.compile(r"xox[abpr]-(?<!\wxox.-)[A-Za-z0-9-]{10,}"), False, True),
    ("Slack webhook", re.compile(
        r"hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"), False, True),
    ("SendGrid key", re.compile(r"SG\.(?<![\w.-]SG\.)[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![\w-])"), False, True),
    ("Telegram bot token", re.compile(r":AA(?<=\d:AA)[A-Za-z0-9_-]{30,}"), False, True),   # bot id checked below
    ("Google API key", re.compile(r"AIza(?<![\w-]AIza)[0-9A-Za-z_-]{35}(?![\w-])"), False, True),
    ("age secret key", re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{50,}"), False, True),
    ("Azure storage key", re.compile(r"AccountKey=(?P<value>[A-Za-z0-9+/]{40,}={0,2})"), False, True),
    ("JWT", re.compile(r"eyJ(?<![\w-]eyJ)[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), False, False),
    ("credentials in URL", re.compile(r"://[^\s/:@\"'<>]{0,256}:(?P<value>[^\s/@\"'<>]{4,256})@"), False, True),
    ("Authorization header", re.compile(
        r"authorization[\"']?[ \t]{0,5}[:=][ \t]{0,5}[\"']?(?:bearer|basic|token)[ \t]{1,5}"
        r"(?P<value>[a-z0-9._~+/=-]{16,})"),
     True, True),
)
_URL_SCHEME = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,30}\Z")
_URL_PLACEHOLDER_PASSWORDS = frozenset({"password", "passwd", "pass", "pwd", "pw", "secret"})
_PLACEHOLDER = re.compile(r"xxx|\.\.\.|<|>|\$\{|\{\{|your[_-]|change[_-]?me|example|placeholder|dummy|redacted", re.I)

# Clear-text credential assignment (warning rule). Keys may carry a prefix (POSTGRES_PASSWORD,
# export DB_PASSWORD) and a short credential suffix (SECRET_KEY_BASE, password2); a free suffix is
# not allowed, because password_hash, password_reset_url or secretary_name are not credentials.
# Bare "token" and "key" are not keywords: they name far too many ordinary things.
_ASSIGN_KEY = (
    r"(?:pass(?:word|wd|phrase)|pwd|(?<![a-z])pass|secret(?:[_-]?(?:access[_-]?)?key)?|api[_-]?key"
    r"|access[_-]?(?:key|token)|auth[_-]?token|client[_-]?secret|private[_-]?key)"
    r"(?:[_-]?(?:\d+|value|plain|text|base))?"
)
_ASSIGN_VALUE = (
    r"[\"']?[ \t]{0,20}(?::=|=>|[:=])[ \t]{0,20}"
    r"(?:\"(?P<dq>[^\"\r\n]{8,256})\"|'(?P<sq>[^'\r\n]{8,256})'|[\"']?(?P<bare>[^\s\"'`,;)]{8,}))"
)
_ASSIGN = re.compile(_ASSIGN_KEY + _ASSIGN_VALUE)                 # runs over the lower-cased text
_ASSIGN_GROUPS = ("dq", "sq", "bare")
# Interpolation, masks and templates: never a literal credential, quoted or not.
_TEMPLATE_VALUE = re.compile(r"\$\{|\$\(|%\(|\{\{|^\$\w+$|^%\w+%$|^\{[\w.]*\}$|^\*+$")
# Code shapes, tested on unquoted values only: a quoted string is a literal even if it has brackets.
_CODE_VALUE = re.compile(
    r"^(?:None|null|nil|undefined|true|false|True|False)$"
    r"|^[\w.]+\("                                    # call: getenv(, os.getenv(, secrets.token_hex(
    r"|^[A-Za-z_][\w.]*\[$"                          # subscript: request.form[, os.environ[
    r"|\bos\.environ\b|\bprocess\.env\b|\bgetenv\b|\binput\("
    r"|^(?:self|this|cls|config|settings|conf|cfg|env|args|opts|options|params|request|req|ctx|context)\.[\w.]+$"
    r"|^Optional\[|^(?:str|string|bytes|SecretStr)\b"
    r"|^(?:~|\.{1,2})?/|^[A-Za-z]:\\"                # a path (PWD=/home/user)
)
# An identifier that names a credential (password_hash, user.password, hashedPassword, DB_PASSWORD) is
# a reference to it, not the credential itself.
# A lower-case word with digits (mypassword123) is a weak password, not a reference: references are
# snake_case with an underscore, camelCase without digits, UPPER_CASE constants or dotted attributes.
_CREDENTIAL_REFERENCE = re.compile(
    r"^(?:_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+|_[a-z][a-z0-9]*|[a-z]+(?:[A-Z][a-z]+)+|[A-Z]+(?:_[A-Z0-9]+)+"
    r"|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)$"
)
_CREDENTIAL_WORD = re.compile(r"pass|pwd|secret|token|key|cred", re.I)


def _assign_skipped(value: str, quoted: bool) -> bool:
    if _PLACEHOLDER.search(value) or _TEMPLATE_VALUE.search(value):
        return True
    if quoted:
        return False
    if _CODE_VALUE.search(value):
        return True
    return bool(_CREDENTIAL_REFERENCE.match(value) and _CREDENTIAL_WORD.search(value))


def find_secrets(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    """Token formats (block) and clear-text assignments (warn); offsets refer to the original text."""
    yield from _original_offsets(_find_secrets(normalise(text), allow), _dropped_positions(text))


def _find_secrets(text: str, allow: Iterable[str]) -> Iterator[Finding]:
    low = text.replace("\u0130", "i").lower()   # U+0130 is the one character that lower-cases to two
    found: List[Finding] = []
    for label, pattern, insensitive, placeholders in _SECRET_PATTERNS:
        for m in pattern.finditer(low if insensitive else text):
            start = m.start()
            if label == "Telegram bot token":
                start = _telegram_bot_id(text, start)
                if start < 0:
                    continue
            whole = text[start:m.end()]
            value = text[m.start("value"):m.end("value")] if "value" in pattern.groupindex else whole
            if whole in allow or value in allow:
                continue
            if placeholders and _PLACEHOLDER.search(value):
                continue
            if label == "credentials in URL" and not _url_credentials(text, m.start(), value):
                continue
            found.append(Finding("secret", start, m.end(), mask(whole), label))
    # One finding per span: a bearer JWT or AWS keys in a URL are reported once.
    found.sort(key=lambda f: (f.start, -f.end))
    kept: List[Finding] = []
    for f in found:
        if not kept or f.start >= kept[-1].end:
            kept.append(f)
    starts = [f.start for f in kept]
    for m in _ASSIGN.finditer(low):
        group = next(g for g in _ASSIGN_GROUPS if m.group(g) is not None)
        start, end = m.start(group), m.end(group)
        value = text[start:end]
        if value in allow or _assign_skipped(value, group != "bare"):
            continue
        i = bisect.bisect_right(starts, end - 1) - 1
        if i >= 0 and kept[i].end > start:
            continue                          # already reported as a token
        kept.append(Finding("secret-assign", start, end, mask(value), "credential assigned in clear text"))
    yield from kept


def _telegram_bot_id(text: str, colon: int) -> int:
    """Start of the 8-10 digit bot id in front of ':AA', or -1."""
    i = colon
    while i > 0 and colon - i <= 10 and text[i - 1].isdigit():
        i -= 1
    return i if 8 <= colon - i <= 10 and not (i > 0 and text[i - 1].isdigit()) else -1


def _url_credentials(text: str, colon_slash: int, password: str) -> bool:
    """scheme://user:password@ with a real scheme in front and a password that is not a stand-in."""
    if not _URL_SCHEME.search(text, max(0, colon_slash - 40), colon_slash):
        return False
    pw = password.lower()
    return pw not in _URL_PLACEHOLDER_PASSWORDS and not pw.startswith(("$", "%", "{", "*", "<"))


def find_pii(text: str, allow: Iterable[str] = (), allow_domains: Iterable[str] = ()) -> Iterator[Finding]:
    """All personal-data detectors over the normalised text; offsets refer to the original text."""
    yield from _original_offsets(_find_pii(normalise(text), allow, allow_domains), _dropped_positions(text))


def _find_pii(text: str, allow: Iterable[str], allow_domains: Iterable[str]) -> Iterator[Finding]:
    yield from find_tckn(text, allow)
    yield from find_es_id(text, allow)
    yield from find_it_cf(text, allow)
    yield from find_nl_bsn(text, allow)
    yield from find_pl_pesel(text, allow)
    yield from find_se_personnummer(text, allow)
    yield from find_iban(text, allow)
    yield from find_card(text, allow)
    yield from find_email(text, allow, allow_domains)
    yield from find_phone(text, allow)
