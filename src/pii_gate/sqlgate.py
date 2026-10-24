"""SQL gate: refuses queries whose output lists name personal-data columns.

Two tiers, so that ordinary business queries keep working:
  core columns     - always sensitive (national IDs, birth dates, card numbers, health, salary ...)
  context columns  - names and contact details; sensitive only when the query touches a person table,
                     otherwise reported as a warning (a supplier's phone is not personal data)
Wrappers that do not reveal the value (COUNT, LEN, IS NULL, first character, year) are allowed.

Column names are compared on their parts: camelCase and multi-word bracketed names are turned into
snake_case and Turkish letters are folded to ASCII before the lists and stems below are applied.
Every step keeps the text the same length, so finding offsets point into the original text.
"""
from __future__ import annotations

import re
from typing import Iterable, Iterator, List, Optional, Set, Tuple

from .detectors import Finding

CORE_COLUMNS: Set[str] = {
    "national_id", "nationalid", "national_identity", "tckn", "tc_kimlik", "tckimlik", "tc_kimlik_no",
    "kimlikno", "kimlik_no", "tcno", "tc_no", "identity_no", "identityno", "ssn", "social_security",
    "social_security_number", "passport", "passport_no", "passportno", "pasaport_no", "pasaportno",
    "birth_date", "birthdate", "dob", "date_of_birth", "dateofbirth", "dogum_tarihi", "dogumtarihi",
    "credit_card", "creditcard", "card_number", "cardnumber", "card_no", "kart_no", "kartno", "pan",
    "mother_name", "mothername", "anne_adi", "anneadi", "father_name", "fathername", "baba_adi", "babaadi",
    "maiden_name", "maidenname", "kizlik_soyadi", "salary", "maas", "wage", "religion", "din",
    "ethnicity", "diagnosis", "tani", "icd", "icd10", "health_record", "medical_record", "biometric",
    "fingerprint", "genetic", "blood_type", "kan_grubu",
    "dni", "nie", "nif", "codice_fiscale", "codicefiscale", "bsn", "burgerservicenummer", "pesel",
    "personnummer", "samordningsnummer",
}
CONTEXT_COLUMNS: Set[str] = {
    "first_name", "firstname", "last_name", "lastname", "surname", "full_name", "fullname", "name",
    "ad", "adi", "soyad", "soyadi", "ad_soyad", "adsoyad", "patient_name", "hasta_adi", "hastaadi",
    "isim", "soyisim", "isim_soyisim", "isimsoyisim",
    "email", "e_mail", "eposta", "e_posta", "mail", "phone", "telephone", "tel", "mobile", "cell",
    "gsm", "telefon", "ceptel", "cep_tel", "cep_telefonu", "address", "adres", "home_address",
    "street", "iban", "account_no", "hesap_no", "plate", "plaka", "ip", "ip_address",
}
PERSON_TABLES: Set[str] = {
    "patient", "hasta", "person", "people", "employee", "staff", "personel", "user", "kullanici",
    "member", "uye", "citizen", "vatandas", "customer_person", "contact", "kisi", "student", "ogrenci",
    "applicant", "aday", "doctor", "hekim", "nurse", "hemsire", "subscriber", "abone", "calisan",
}

# Stems matched on the snake_case form of a column name, at part boundaries. Short words that mean
# something else too (id, name, tani, icd, pan, din) stay exact-match only, in the sets above.
_CORE_STEMS = re.compile(
    r"(?:^|_)tc_?kimlik"
    r"|(?:^|_)kimlik_?(?:no|nr|num|numara|numarasi)(?:_|$)"
    r"|^tc$|_tc$|^tc_?(?:no|nr|num|numara|numarasi)$"           # not tc_*: tc_id, tc_status (test cases)
    r"|(?:^|_)national_?id"
    r"|(?:^|_)ssn(?:_|$)|(?:^|_)social_?security"
    r"|(?:^|_)pas+a?port(?:_?(?:no|nr|num|number|numarasi))?$"
    r"|(?:^|_)dogum_?(?:tar|gun)"
    r"|(?:^|_)(?:birth_?date|date_?of_?birth|birth_?day)(?:_|$)|(?:^|_)dob$"
    r"|(?:^|_)(?:credit_?card|card_?(?:number|no|num)|kart_?(?:no|num|numarasi|number))(?:_|$)"
    r"|(?:^|_)(?:anne|baba|mother|father)_?(?:adi|name)$|(?:^|_)(?:kizlik_?soyadi|maiden_?name)$"
    r"|(?:^|_)(?:salary|maas|wage)(?:_|$)"
    r"|(?:^|_)diagnos[ie]s(?:_?(?:kodu|kod|code|adi|name|text))?$|(?:^|_)(?:tani|icd(?:_?10)?)_?(?:kodu|kod|code|adi)$"
    r"|(?:^|_)(?:blood_?type|kan_?grubu)$"
)
_CONTEXT_STEMS = re.compile(
    r"(?:^|_)(?:cep_?|ev_?|is_?)?tel(?:efon)?(?:u|i)?(?:_?(?:no|nr|num|numarasi))?_?\d*$"
    r"|(?:^|_)gsm(?:_?(?:no|nr|num|numarasi))?_?\d*$"
    r"|(?:^|_)(?:e_?)?(?:mail|posta)(?:_?(?:address|adresi))?_?\d*$"
    r"|(?:^|_)(?:tele)?phone(?:_?(?:number|no|nr|num))?_?\d*$"
    r"|(?:^|_)address(?:_?line)?_?\d*$"
    r"|(?:^|_)adres"
    r"|^(?:(?:hasta|personel|calisan|kisi|ogrenci|uye|kullanici|hekim|doktor|musteri)_?)?"
    r"(?:ad|adi|soyad|soyadi|isim|soyisim)(?:_?(?:soyad|soyadi|soyisim))?$"
    r"|(?:^|_)patient_?name$|(?:^|_)(?:first|last|full|middle|given|family|sur)_?name$"
    r"|(?:^|_)iban(?:_?no)?$"
)
# Table-name parts that start like a person stem but are not people (hastane = hospital,
# hastalik = disease), and naming prefixes glued to a table name (tblPatients, inpatient).
_NOT_PERSON_PARTS = ("hastane", "hastalik")
_TABLE_PREFIXES = ("tbl", "vw", "v", "dim", "fact", "stg", "tmp", "temp", "in", "out")

_ID = r"[\w.\[\]\"`]+"
_ARG = r"[^()]*(?:\([^()]*\)[^()]*)*"          # an argument list with one level of nested parentheses
_PAREN_WRAPPERS = (
    re.compile(r"\bcount\s*\(" + _ARG + r"\)", re.I),
    re.compile(r"\b(?:len|length|datalength|char_length)\s*\(\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\bleft\s*\(\s*" + _ID + r"\s*,\s*1\s*\)", re.I),
    re.compile(r"\b(?:substr|substring)\s*\(\s*" + _ID + r"\s*,\s*1\s*,\s*1\s*\)", re.I),
    re.compile(r"\b(?:year|month)\s*\(\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\bdatepart\s*\(\s*(?:year|yyyy|yy|month|mm)\s*,\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\bextract\s*\(\s*(?:year|month)\s+(?:from\s+)?" + _ID + r"\s*\)", re.I),
    re.compile(r"\bto_char\s*\(\s*" + _ID + r"\s*,\s*'(?:yyyy|yyyy-mm|mm)'\s*\)", re.I),
    re.compile(r"\bdatediff\s*\(\s*(?:year|yyyy|yy)\s*,\s*" + _ID + r"\s*,\s*[^(),]*(?:\([^()]*\))?\s*\)", re.I),
    re.compile(r"\bdate_trunc\s*\(\s*'(?:year|month)'\s*,\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\b(?:hashbytes|md5|sha2?_?\d*)\s*\(" + _ARG + r"\)", re.I),
    re.compile(r"\b(?:avg|sum|min|max)\s*\(\s*(?:distinct\s+)?(?:[\w\[\]\"`]+\.)?[\[\"`]?(?:\w+_)?(?:salary|maas|wage)"
               r"(?:_\w+)?[\]\"`]?\s*\)", re.I),
)
_IS_NULL = re.compile(r"(?<![\w.\[\]\"`])" + _ID + r"\s+is\s+(?:not\s+)?null", re.I)
_ALLOWED_WRAPPERS = _PAREN_WRAPPERS + (_IS_NULL,)
# String literals kept as they are because the wrappers above test them: date-part names and formats.
_FORMAT_LITERALS = frozenset({"year", "yyyy", "yy", "month", "mm", "yyyy-mm", "quarter"})

# Keyword patterns run over the lower-cased text. Each starts with its keyword and checks the word
# boundary with a lookbehind placed after it, so the regex engine jumps between occurrences of the
# keyword instead of trying every position: on a 5 MB file that is the difference between
# milliseconds and a large part of a second per pattern.
def _kw(*words: str) -> str:
    return "(?:" + "|".join(rf"{w}(?<!\w{w})" for w in words) + r")\b"


_SELECT = re.compile(r"select(?<![\w$.]select)\b")              # not el.select(), $select
_FROM = re.compile(_kw("from"))
_DML = re.compile(_kw("insert", "update", "delete", "merge"))
_RETURNING = re.compile(_kw("returning"))
_RETURNING_END = re.compile(r";|" + _kw("into"))
_OUTPUT = re.compile(_kw("output") + r"\s+(?=(?:inserted|deleted)\b)")
_OUTPUT_END = re.compile(r";|" + _kw("into", "from", "where", "values", "select", "default"))
_COPY_WORD = re.compile(_kw("copy"))                            # also matches psql's \copy
_TO = re.compile(_kw("to"))
_BCP_WORD = re.compile(_kw("bcp"))
_OUT = re.compile(_kw("out"))
_TABLE = r"[#\w.\[\]\"`]+"
_COPY = re.compile(r"(?P<cmd>\\copy|copy(?<!\wcopy))\s+(?P<table>" + _TABLE + r")(?:\s*\((?P<cols>[^()]{0,2000})\))?"
                   r"\s+to\b(?P<target>\s+(?:'|e'|stdout\b|program\b|pstdout\b))?")
_BCP = re.compile(_kw("bcp") + r"\s+(?P<table>" + _TABLE + r")\s+out\b")
_TABLE_REFS = re.compile(_kw("from", "join", "update", "into") + r"\s+(" + _TABLE + r")")

_BLANK_LINE = re.compile(r"\n[ \t\r]*\n")
_SHORT_LIST = 2000        # a list with no FROM before the next blank line ends here
_LONG_LIST = 20000        # a list that does reach a FROM (long ORM column lists) ends here at the latest
# A "list" that reads as prose: two of these words, or a sentence that ends right after its first
# word, or a keyword quoted as a mention (`select`, "SELECT"). SQL keywords are deliberately absent.
_STOP_WORDS = re.compile(
    r"(?<![\w.])(?<!\bas )(?:the|a|an|of|to|with|that|this|which|these|those|are|be|it|its|was|would|could"
    r"|should|bir|ve|ile|icin|bu|su|olan|is(?!\s+(?:not|null|true|false|distinct|unknown)\b))(?![\w.])", re.I)
_PROSE_START = re.compile(r"[`'\",.;:!?)]|\s*[\w*]+[.!?:;](?:\s|$)")

_STRING_OR_COMMENT = re.compile(r"'|--(?=\s|\Z)|/\*")
_NOT_NEWLINE = re.compile(r"[^\n]+")
_TR_FOLD = {"\u00e7": "c", "\u011f": "g", "\u0131": "i", "\u00f6": "o", "\u015f": "s", "\u00fc": "u",
            "\u00c7": "C", "\u011e": "G", "\u0130": "I", "\u00d6": "O", "\u015e": "S", "\u00dc": "U",
            "\u00e2": "a", "\u00ee": "i", "\u00fb": "u", "\u00c2": "A", "\u00ce": "I", "\u00db": "U"}
_TR_FOLD_RE = re.compile("[" + "".join(_TR_FOLD) + "]")
_BRACKETED = re.compile(r"\[([^\[\]\n]{1,128})\]")
_QUOTED_NAME = re.compile(r"\"([^\"\n]{1,128})\"|`([^`\n]{1,128})`")
_NAME_SPACE = re.compile(r"[\s-]")
_FROM_IN_FUNC = re.compile(_kw("extract", "trim", "substring", "position", "overlay") + r"\s*\([^()]*?\bfrom\b")
_IDENT = re.compile(r"[^\W\d]\w*")
_DELIMITERS = re.compile(r"[\[\]\"`]")
_STAR = re.compile(r"(?:^|[\s,])(?:(?:\[[^\]\n]*\]|\"[^\"\n]*\"|`[^`\n]*`|\w+)\.)*\*(?=\s|,|\)|;|$)")
_CAMEL_1 = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL_2 = re.compile(r"([a-z0-9])([A-Z])")
_UNDERSCORES = re.compile(r"_+")
_TABLE_PARTS = re.compile(r"[^a-z0-9]+")


def _lower(text: str) -> str:
    """Lower case of the same length (U+0130 is the one character that lower-cases to two)."""
    return text.replace("\u0130", "i").lower()


def looks_like_sql(text: str) -> bool:
    """Cheap pre-check, every test a linear search: a SELECT followed somewhere by a FROM, a
    RETURNING after an INSERT/UPDATE/DELETE, an OUTPUT inserted./deleted. list, a COPY ... TO or a
    bcp ... out. (A lazy `select.*?from` regex is quadratic on text with many SELECTs and no FROM.)"""
    low = text.lower()
    if "select" in low:
        m = _SELECT.search(low)
        if m and _FROM.search(low, m.end()):
            return True
    if "returning" in low:
        m = _RETURNING.search(low)
        if m and _DML.search(low, 0, m.start()):
            return True
    if "output" in low and _OUTPUT.search(low):
        return True
    if "copy" in low:
        m = _COPY_WORD.search(low)
        if m and _TO.search(low, m.end()):
            return True
    if "bcp" in low:
        m = _BCP_WORD.search(low)
        if m and _OUT.search(low, m.end()):
            return True
    return False


# --------------------------------------------------------------------------- text preparation
def _pad(segment: str) -> str:
    """Spaces of the same length, newlines kept (so line numbers stay right)."""
    return _NOT_NEWLINE.sub(lambda m: " " * len(m.group()), segment)


def _string_end(text: str, i: int) -> int:
    """Index of the quote closing a literal whose content starts at i ('' is an escaped quote), or -1."""
    while True:
        j = text.find("'", i)
        if j < 0 or not text.startswith("'", j + 1):
            return j
        i = j + 2


def _blank_strings_and_comments(text: str) -> Tuple[str, List[Tuple[int, int]]]:
    """Comments and string literals replaced by same-length padding, in one linear pass (a lazy
    /*.*?*/ regex is quadratic on an unclosed comment). `--` starts a comment only before whitespace
    or the end, so `psql --host=db` is not one. Returns the text and the (start, end) of string
    literals that themselves hold SQL (psql -c '...', sp_executesql N'...'), to be scanned separately."""
    out: List[str] = []
    nested: List[Tuple[int, int]] = []
    pos = 0
    while True:
        m = _STRING_OR_COMMENT.search(text, pos)
        if not m:
            out.append(text[pos:])
            break
        i = m.start()
        out.append(text[pos:i])
        token = m.group()
        if token == "'":
            j = _string_end(text, i + 1)
            if j < 0:                                  # unclosed: leave the quote, scan on
                out.append("'")
                pos = i + 1
                continue
            inner = text[i + 1:j]
            if inner.lower() in _FORMAT_LITERALS:
                out.append(text[i:j + 1])
            else:
                if looks_like_sql(inner):
                    nested.append((i + 1, j))
                out.append("'" + _pad(inner) + "'")
            pos = j + 1
        else:
            j = text.find("\n", i) if token == "--" else text.find("*/", i + 2)
            end = len(text) if j < 0 else (j if token == "--" else j + 2)
            out.append(_pad(text[i:end]))
            if j < 0:
                break
            pos = end
    return "".join(out), nested


def _nested_canvas(raw: str, nested: List[Tuple[int, int]]) -> str:
    """All SQL-holding literals in one text of the original length: the literals' content in place,
    everything else padded, and each literal's quotes turned into newlines so that two neighbouring
    literals are separated by a blank line (a list never runs from one into the next)."""
    pieces: List[str] = []
    last = 0
    for start, end in nested:
        pieces.append(_pad(raw[last:start - 1]))
        pieces.append("\n")
        pieces.append(raw[start:end].replace("''", " '"))  # escaped quotes inside the literal
        pieces.append("\n")
        last = end + 1
    pieces.append(_pad(raw[last:]))
    return "".join(pieces)


def _fold(text: str) -> str:
    if text.isascii():
        return text
    return _TR_FOLD_RE.sub(lambda m: _TR_FOLD[m.group()], text)


def _join_words(m: "re.Match[str]") -> str:
    return _NAME_SPACE.sub("_", m.group())


def _snake(name: str) -> str:
    s = _CAMEL_2.sub(r"\1_\2", _CAMEL_1.sub(r"\1_\2", name)).lower()
    return _UNDERSCORES.sub("_", s).strip("_")


# --------------------------------------------------------------------------- person tables
def _clean(name: str) -> str:
    return _DELIMITERS.sub("", name).lstrip("#").split(".")[-1]


def is_person_table(name: str, person_tables: Iterable[str]) -> bool:
    """True when a part of the table name starts with a person stem: hastalar, tbl_patient, v_patient,
    Hasta_Kayit, kullanicilar, AspNetUsers. hastane, remember_tokens and buyers are not person tables."""
    snake = _snake(_clean(_fold(name)))
    parts = [p for p in _TABLE_PARTS.split(snake) if p]
    for part in parts:
        if part.startswith(_NOT_PERSON_PARTS):
            continue
        candidates = [part] + [part[len(p):] for p in _TABLE_PREFIXES if part.startswith(p) and len(part) > len(p)]
        for stem in person_tables:
            if "_" in stem:
                if re.search(r"(?:^|_)" + re.escape(stem), snake):
                    return True
            elif any(c.startswith(stem) for c in candidates):
                return True
    return False


def _person_context(text: str, low: str, person_tables: Tuple[str, ...]) -> bool:
    seen: Set[str] = set()
    for m in _TABLE_REFS.finditer(low):
        key = m.group(1)
        if key in seen:
            continue
        seen.add(key)
        if is_person_table(text[m.start(1):m.end(1)], person_tables):
            return True
    return False


def person_context(text: str, person_tables: Iterable[str]) -> bool:
    """True when the text refers (FROM/JOIN/UPDATE/INTO) to a table that holds people."""
    return _person_context(text, _lower(text), tuple(person_tables))


# --------------------------------------------------------------------------- lists
def _is_prose(cols: str) -> bool:
    if _PROSE_START.match(cols):
        return True
    hits = 0
    for _ in _STOP_WORDS.finditer(cols):
        hits += 1
        if hits >= 2:
            return True
    return False


class _NextMatch:
    """The next match of a pattern at or after a position, searched again only when the position has
    passed the cached match, so that scanning many SELECTs stays linear."""

    def __init__(self, pattern: "re.Pattern[str]", text: str):
        self.pattern, self.text = pattern, text
        self.searched_from = -1
        self.match: Optional["re.Match[str]"] = None

    def at_or_after(self, pos: int) -> Optional["re.Match[str]"]:
        if self.searched_from < 0 or pos < self.searched_from or (self.match is not None and self.match.start() < pos):
            self.match = self.pattern.search(self.text, pos)
            self.searched_from = pos
        return self.match


def _select_lists(text: str, low: str) -> Iterator[Tuple[int, int]]:
    """(start, end) of each SELECT list: up to its FROM when that comes before the next blank line,
    otherwise up to the blank line, at most _SHORT_LIST characters. Prose is skipped."""
    n = len(text)
    froms, blanks = _NextMatch(_FROM, low), _NextMatch(_BLANK_LINE, text)
    pos = 0
    while True:
        m = _SELECT.search(low, pos)
        if not m:
            return
        start = m.end()
        pos = start
        blank = blanks.at_or_after(start)
        para_end = blank.start() if blank else n
        f = froms.at_or_after(start)
        if f and f.start() < para_end and f.start() - start <= _LONG_LIST:
            end, resume = f.start(), f.end()
        else:
            end = resume = min(para_end, start + _SHORT_LIST)
        if _is_prose(text[start:end]):
            continue                                                 # resume right after this SELECT
        pos = resume
        yield start, end


def _keyword_lists(text: str, low: str, keyword: "re.Pattern[str]", end_re: "re.Pattern[str]",
                   after: int = 0) -> Iterator[Tuple[int, int]]:
    n = len(text)
    pos = after
    while True:
        m = keyword.search(low, pos)
        if not m:
            return
        start = m.end()
        limit = min(n, start + _SHORT_LIST)
        blank = _BLANK_LINE.search(text, start, limit)
        if blank:
            limit = blank.start()
        e = end_re.search(low, start, limit)
        end = e.start() if e else limit
        pos = max(end, start + 1)
        if not _is_prose(text[start:end]):
            yield start, end


# --------------------------------------------------------------------------- scanning
class _Rules:
    def __init__(self, extra_core: Iterable[str], extra_person: Iterable[str], ignore: Iterable[str]):
        self.ignored = {c.lower() for c in ignore}
        self.core = (CORE_COLUMNS | {c.lower() for c in extra_core}) - self.ignored
        self.context = CONTEXT_COLUMNS - self.ignored
        self.person_tables = tuple(PERSON_TABLES | {t.lower() for t in extra_person})

    def tier(self, raw: str) -> Optional[str]:
        low, snake = raw.lower(), _snake(raw)
        if low in self.ignored or snake in self.ignored:
            return None
        if low in self.core or snake in self.core or _CORE_STEMS.search(snake):
            return "core"
        if low in self.context or snake in self.context or _CONTEXT_STEMS.search(snake):
            return "context"
        return None


def _blank_wrappers(cols: str) -> str:
    if "(" in cols:
        for wrapper in _PAREN_WRAPPERS:
            cols = wrapper.sub(lambda w: _pad(w.group()), cols)
    if "null" in cols.lower():
        cols = _IS_NULL.sub(lambda w: _pad(w.group()), cols)
    return cols


def _scan_list(text: str, start: int, end: int, base: int, person: bool, rules: _Rules,
               where: str) -> Iterator[Finding]:
    cols = _blank_wrappers(text[start:end])
    star = _STAR.search(cols)
    if star and person:
        pos = base + start + star.end() - 1
        yield Finding("sql-star", pos, pos + 1, "*", f"{where} * on a person table")
    cols = _DELIMITERS.sub(" ", _QUOTED_NAME.sub(_join_words, cols))
    seen: Set[str] = set()
    for ident in _IDENT.finditer(cols):
        raw = ident.group()
        name = _snake(raw) or raw.lower()
        if name in seen:
            continue
        seen.add(name)
        tier = rules.tier(raw)
        if tier is None:
            continue
        pos = base + start + ident.start()
        if tier == "core":
            yield Finding("sql-pii", pos, pos + len(raw), name, f"sensitive column in {where} list")
        elif person:
            yield Finding("sql-pii", pos, pos + len(raw), name, "personal column in a person-table query")
        else:
            yield Finding("sql-pii-context", pos, pos + len(raw), name, "contact/name column outside a person table")


def _scan_statement(raw: str, rules: _Rules, nested_level: bool = False) -> Iterator[Finding]:
    text, nested = _blank_strings_and_comments(_fold(raw))
    text = _BRACKETED.sub(_join_words, text)
    low = _lower(text)
    low = _FROM_IN_FUNC.sub(lambda m: m.group()[:-4] + "    ", low)   # EXTRACT(YEAR FROM x) does not end a list
    person = _person_context(text, low, rules.person_tables)
    if "select" in low:
        for start, end in _select_lists(text, low):
            yield from _scan_list(text, start, end, 0, person, rules, "SELECT")
    if "returning" in low:
        m = _DML.search(low)
        if m:
            for start, end in _keyword_lists(text, low, _RETURNING, _RETURNING_END, m.end()):
                yield from _scan_list(text, start, end, 0, person, rules, "RETURNING")
    if "output" in low:
        for start, end in _keyword_lists(text, low, _OUTPUT, _OUTPUT_END):
            yield from _scan_list(text, start, end, 0, person, rules, "OUTPUT")
    if "copy" in low or "bcp" in low:
        yield from _scan_exports(text, low, rules)
    if nested and not nested_level:
        yield from _scan_statement(_nested_canvas(raw, nested), rules, nested_level=True)


def _scan_exports(text: str, low: str, rules: _Rules) -> Iterator[Finding]:
    """Whole-table exports of a person table: Postgres COPY with TO, psql's backslash-copy, bcp with out."""
    for m in _COPY.finditer(low):
        if m.group("cmd") != "\\copy" and not m.group("target"):
            continue                                   # "copy users to the clipboard" is prose
        table = text[m.start("table"):m.end("table")]
        person = is_person_table(table, rules.person_tables)
        if m.group("cols") is not None:
            yield from _scan_list(text, m.start("cols"), m.end("cols"), 0, person, rules, "COPY")
        elif person:
            yield Finding("sql-star", m.start(), m.end("table"), _clean(table).lower(), "table export of a person table")
    for m in _BCP.finditer(low):
        table = text[m.start("table"):m.end("table")]
        if is_person_table(table, rules.person_tables):
            yield Finding("sql-star", m.start(), m.end("table"), _clean(table).lower(), "table export of a person table")


def find_sql(text: str, extra_core: Iterable[str] = (), extra_person: Iterable[str] = (),
             ignore: Iterable[str] = ()) -> Iterator[Finding]:
    """Findings for the output lists of the SQL in `text`. Offsets point into `text` itself."""
    if not looks_like_sql(text):
        return
    yield from _scan_statement(text, _Rules(extra_core, extra_person, ignore))
