"""SQL gate: refuses SELECT lists that would output personal-data columns.

Two tiers, so that ordinary business queries keep working:
  core columns     - always sensitive (national IDs, birth dates, card numbers, health, salary ...)
  context columns  - names and contact details; sensitive only when the query touches a person table,
                     otherwise reported as a warning (a supplier's phone is not personal data)
Wrappers that do not reveal the value (COUNT, LEN, IS NULL, first character, year) are allowed.
"""
from __future__ import annotations

import re
from typing import Iterable, Iterator, Set

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
    "email", "e_mail", "eposta", "e_posta", "mail", "phone", "telephone", "tel", "mobile", "cell",
    "gsm", "telefon", "ceptel", "cep_tel", "cep_telefonu", "address", "adres", "home_address",
    "street", "iban", "account_no", "hesap_no", "plate", "plaka", "ip", "ip_address",
}
PERSON_TABLES: Set[str] = {
    "patient", "hasta", "person", "people", "employee", "staff", "personel", "user", "kullanici",
    "member", "uye", "citizen", "vatandas", "customer_person", "contact", "kisi", "student", "ogrenci",
    "applicant", "aday", "doctor", "hekim", "nurse", "hemsire", "subscriber", "abone",
}

_SELECT_LIST = re.compile(r"\bselect\b(?P<cols>.*?)(?:\bfrom\b|$)", re.I | re.S)
_TABLE_REFS = re.compile(r"\b(?:from|join|update|into)\s+([\w.\[\]\"`]+)", re.I)
_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
_STRING = re.compile(r"'(?:[^']|'')*'")
_ID = r"[\w.\[\]\"`]+"
_ALLOWED_WRAPPERS = (
    re.compile(r"\bcount\s*\(\s*(?:distinct\s+)?[^()]*\)", re.I),
    re.compile(r"\b(?:len|length|datalength|char_length)\s*\(\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\bleft\s*\(\s*" + _ID + r"\s*,\s*1\s*\)", re.I),
    re.compile(r"\b(?:substr|substring)\s*\(\s*" + _ID + r"\s*,\s*1\s*,\s*1\s*\)", re.I),
    re.compile(r"\b(?:year|month)\s*\(\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\bdatepart\s*\(\s*(?:year|yyyy|yy|month|mm)\s*,\s*" + _ID + r"\s*\)", re.I),
    re.compile(r"\bextract\s*\(\s*(?:year|month)\s+from\s+" + _ID + r"\s*\)", re.I),
    re.compile(r"\bto_char\s*\(\s*" + _ID + r"\s*,\s*'(?:yyyy|yyyy-mm|mm)'\s*\)", re.I),
    re.compile(_ID + r"\s+is\s+(?:not\s+)?null", re.I),
)


def looks_like_sql(text: str) -> bool:
    return bool(re.search(r"\bselect\b.*?\bfrom\b", text, re.I | re.S))


def _clean(name: str) -> str:
    return re.sub(r"[\[\]\"`]", "", name).lower().split(".")[-1]


def person_context(text: str, person_tables: Iterable[str]) -> bool:
    tables = [_clean(t) for t in _TABLE_REFS.findall(text)]
    return any(p in t for t in tables for p in person_tables)


def find_sql(text: str, extra_core: Iterable[str] = (), extra_person: Iterable[str] = (),
             ignore: Iterable[str] = ()) -> Iterator[Finding]:
    if not looks_like_sql(text):
        return
    ignored = {c.lower() for c in ignore}
    core = (CORE_COLUMNS | {c.lower() for c in extra_core}) - ignored
    context = CONTEXT_COLUMNS - ignored
    person_tables = PERSON_TABLES | {t.lower() for t in extra_person}
    stripped = _STRING.sub("''", _COMMENT.sub(" ", text))
    person = person_context(stripped, person_tables)
    for m in _SELECT_LIST.finditer(stripped):
        cols = m.group("cols")
        offset = m.start("cols")
        if re.search(r"(?:^|[\s,])(?:\w+\.)?\*(?:\s|,|$)", cols) and person:
            yield Finding("sql-star", m.start(), m.end(), "*", "SELECT * on a person table")
        for wrapper in _ALLOWED_WRAPPERS:
            cols = wrapper.sub(lambda w: " " * (w.end() - w.start()), cols)
        seen = set()
        for ident in re.finditer(r"[A-Za-z_][\w]*", re.sub(r"[\[\]\"`]", " ", cols)):
            name = ident.group().lower()
            if name in seen:
                continue
            seen.add(name)
            pos = offset + ident.start()
            if name in core:
                yield Finding("sql-pii", pos, pos + len(name), name, "sensitive column in SELECT list")
            elif name in context:
                if person:
                    yield Finding("sql-pii", pos, pos + len(name), name, "personal column in a person-table query")
                else:
                    yield Finding("sql-pii-context", pos, pos + len(name), name,
                                  "contact/name column outside a person table")
