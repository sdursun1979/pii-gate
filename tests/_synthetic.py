"""Synthetic test values. Generated from arbitrary digits; they belong to nobody.

Each helper computes the real check digits so that the detectors' checksum logic is exercised.
"""


def tckn(prefix9: str) -> str:
    d = [int(c) for c in prefix9]
    assert len(d) == 9 and d[0] != 0
    d10 = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    d11 = (sum(d) + d10) % 10
    return prefix9 + str(d10) + str(d11)


def iban(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    number = int("".join(str(int(ch, 36)) for ch in rearranged))
    check = 98 - number % 97
    return f"{country}{check:02d}{bban}"


def card(prefix: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return prefix + str((10 - total % 10) % 10)


TCKN_A = tckn("123456789")
TCKN_B = tckn("987654321")
IBAN_TR = iban("TR", "0001200912345678901234")
IBAN_GB = iban("GB", "NWBK60161331926820")
CARD_VISA = card("453957876362148")
CARD_MC = card("540112345678901")
AWS_KEY = "AKIAIOSFODNN7QWERTYUX"[:20]
OPENAI_KEY = "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0k1L2"
GITHUB_TOKEN = "ghp_" + "A" * 36
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"

_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_CF_ODD = dict(zip("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", (
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
    2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23)))


def dni(digits8: str) -> str:
    return digits8 + _DNI_LETTERS[int(digits8) % 23]


def nie(prefix: str, digits7: str) -> str:
    return prefix + digits7 + _DNI_LETTERS[int(str("XYZ".index(prefix)) + digits7) % 23]


def codice_fiscale(first15: str) -> str:
    total = sum(_CF_ODD[ch] if i % 2 == 0 else (int(ch) if ch.isdigit() else ord(ch) - 65)
                for i, ch in enumerate(first15))
    return first15 + chr(65 + total % 26)


def bsn(digits8: str) -> str:
    check = sum(int(c) * w for c, w in zip(digits8, range(9, 1, -1))) % 11
    assert check < 10, "pick other digits"
    return digits8 + str(check)


def pesel(digits10: str) -> str:
    total = sum(int(c) * w for c, w in zip(digits10, (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)))
    return digits10 + str((10 - total % 10) % 10)


def personnummer(digits9: str) -> str:
    """Nine digits (YYMMDD plus three serial digits) plus the Luhn digit, as the ten digits without separator."""
    total = 0
    for i, ch in enumerate(reversed(digits9)):
        d = int(ch) * (2 if i % 2 == 0 else 1)
        total += d - 9 if d > 9 else d
    return digits9 + str((10 - total % 10) % 10)


DNI_A = dni("48573920")
NIE_A = nie("Y", "2846193")
CF_A = codice_fiscale("TSTPRS90A41Z404")        # synthetic: female, 1 January 1990, born abroad
CF_OMOCODIA = codice_fiscale("TSTPRS90A41Z40Q")  # last digit written as a letter
CF_BAD_DAY = codice_fiscale("TSTPRS90A35Z404")   # check character fine, day 35 impossible
BSN_A = bsn("10203040")
PESEL_A = pesel("9001011234")                    # 1 January 1990
PESEL_BAD_DATE = pesel("9013011234")             # month 13
_PNR = personnummer("900101123")                 # 1 January 1990, serial 123
PNR_A = _PNR[:6] + "-" + _PNR[6:]
PNR_PLUS = PNR_A.replace("-", "+")               # same digits, written for a person over 100
_SAM = personnummer("900161123")
SAMORDNING_A = _SAM[:6] + "-" + _SAM[6:]         # coordination number: day 1 + 60
_BAD = personnummer("901301123")
PNR_BAD_DATE = _BAD[:6] + "-" + _BAD[6:]         # month 13
