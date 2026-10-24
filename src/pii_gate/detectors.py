"""Pattern detectors for personal data and secrets.

Every detector yields Finding objects. A Finding never carries the matched value,
only a masked sample (first character + "***"), so findings are safe to log and
safe to show to the agent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Iterable, Iterator


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

# --------------------------------------------------------------------------- TCKN
_TCKN = re.compile(r"(?<!\d)\d{11}(?!\d)")


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


# --------------------------------------------------------------------------- other national IDs
_DNI = re.compile(r"(?<![A-Za-z0-9])(?P<num>\d{8}|[XYZ]\d{7})-?(?P<letter>[A-Z])(?![A-Za-z0-9])")
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_id_valid(num: str, letter: str) -> bool:
    """Spanish DNI (8 digits) or NIE (X/Y/Z + 7 digits): the letter is the number mod 23."""
    digits = str("XYZ".index(num[0])) + num[1:] if num[0] in "XYZ" else num
    if len(set(digits)) == 1:
        return False
    return _DNI_LETTERS[int(digits) % 23] == letter


def find_es_id(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _DNI.finditer(text):
        compact = m.group("num") + m.group("letter")
        if compact in WELL_KNOWN_TEST_VALUES or compact in allow or m.group() in allow:
            continue
        if es_id_valid(m.group("num"), m.group("letter")):
            yield Finding("es-dni", m.start(), m.end(), mask(compact), "Spanish DNI/NIE, check letter valid")


_CF_DIGIT = "[0-9LMNPQRSTUV]"   # omocodia: digits may be replaced by these letters
_CF = re.compile(
    rf"(?<![A-Za-z0-9])[A-Z]{{6}}{_CF_DIGIT}{{2}}[ABCDEHLMPRST]{_CF_DIGIT}{{2}}[A-Z]{_CF_DIGIT}{{3}}[A-Z](?![A-Za-z0-9])"
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
_BSN = re.compile(r"(?<!\d)\d{9}(?!\d)")
_BSN_LABEL = re.compile(r"(?i)\b(?:bsn|burgerservicenummer|sofi(?:nummer)?)\b")
_PESEL = re.compile(r"(?<!\d)\d{11}(?!\d)")
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
_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Z0-9])")
IBAN_LENGTHS = {
    "AE": 23, "AT": 20, "AZ": 28, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24,
    "DE": 22, "DK": 18, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FR": 27, "GB": 22,
    "GE": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27,
    "KW": 30, "KZ": 20, "LT": 20, "LU": 20, "LV": 21, "MT": 31, "NL": 18, "NO": 15,
    "PL": 28, "PT": 25, "QA": 29, "RO": 24, "SA": 24, "SE": 24, "SK": 24, "TR": 26,
}


def iban_valid(compact: str) -> bool:
    cc = compact[:2]
    if not cc.isalpha() or not compact[2:4].isdigit():
        return False
    if cc in IBAN_LENGTHS and len(compact) != IBAN_LENGTHS[cc]:
        return False
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


def find_iban(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _IBAN.finditer(text):
        compact = m.group().replace(" ", "")
        if compact in WELL_KNOWN_TEST_VALUES or compact in allow or not iban_valid(compact):
            continue
        yield Finding("iban", m.start(), m.end(), mask(compact), f"IBAN ({compact[:2]}), checksum valid")


# --------------------------------------------------------------------------- cards
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


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


def find_card(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if not 13 <= len(digits) <= 19 or digits[0] not in "3456":
            continue
        if len(set(digits)) == 1 or not luhn_valid(digits):
            continue
        if digits in WELL_KNOWN_TEST_VALUES or digits in allow:
            continue
        yield Finding("card", m.start(), m.end(), mask(digits), "payment card number, Luhn valid")


# --------------------------------------------------------------------------- e-mail
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w.-])")


def find_email(text: str, allow: Iterable[str] = (), allow_domains: Iterable[str] = ()) -> Iterator[Finding]:
    domains = tuple("@" + d.lower().lstrip("@") for d in allow_domains)
    for m in _EMAIL.finditer(text):
        value = m.group()
        low = value.lower()
        if value in allow or low.endswith(RESERVED_EMAIL_SUFFIXES) or (domains and low.endswith(domains)):
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
_SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("OpenAI/Anthropic-style key", re.compile(r"(?<![\w-])sk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"(?<!\w)(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("Slack token", re.compile(r"(?<!\w)xox[abpr]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])")),
    ("JWT", re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
)
_PLACEHOLDER = re.compile(r"xxx|\.\.\.|<|>|\$\{|\{\{|your[_-]|change[_-]?me|example|placeholder|dummy|redacted", re.I)
_ASSIGN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'`,;)]{8,})"
)
_CODE_VALUE = re.compile(r"[(){}$%]|os\.environ|getenv|process\.env|input\(|None|null|true|false", re.I)


def find_secrets(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for label, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group()
            if value in allow or (label != "private key" and _PLACEHOLDER.search(value)):
                continue
            yield Finding("secret", m.start(), m.end(), mask(value), label)
    for m in _ASSIGN.finditer(text):
        value = m.group("value")
        if value in allow or _PLACEHOLDER.search(value) or _CODE_VALUE.search(value):
            continue
        yield Finding("secret-assign", m.start("value"), m.end("value"), mask(value), "credential assigned in clear text")


def find_pii(text: str, allow: Iterable[str] = (), allow_domains: Iterable[str] = ()) -> Iterator[Finding]:
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
