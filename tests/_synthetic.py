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


def be_rrn(digits9: str, born_2000_or_later: bool = False) -> str:
    """Nine digits (YYMMDD plus a three-digit serial) plus the two check digits: 97 - (n mod 97),
    with a 2 in front of n for people born in 2000 or later."""
    n = int(("2" if born_2000_or_later else "") + digits9)
    return digits9 + f"{97 - n % 97:02d}"


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
RRN_A = be_rrn("900101123")                      # 1 January 1990, serial 123
RRN_DOTTED = f"{RRN_A[0:2]}.{RRN_A[2:4]}.{RRN_A[4:6]}-{RRN_A[6:9]}.{RRN_A[9:]}"
RRN_2000 = be_rrn("050101123", born_2000_or_later=True)   # 1 January 2005
RRN_BIS = be_rrn("902101123")                    # bis number: month + 20
RRN_BAD_DATE = be_rrn("901301123")               # month 13


# --------------------------------------------------------------------------- formatting helpers
def grouped(value: str, size: int = 4, sep: str = " ") -> str:
    return sep.join(value[i:i + size] for i in range(0, len(value), size))


def fullwidth(value: str) -> str:
    """ASCII digits and capital letters as their fullwidth forms (U+FF10.., U+FF21..)."""
    return "".join(chr(ord(c) - 0x30 + 0xFF10) if c.isdigit() else
                   chr(ord(c) - 0x41 + 0xFF21) if "A" <= c <= "Z" else c for c in value)


def tckn_grouped(value: str, sep: str = " ") -> str:
    return sep.join((value[:3], value[3:6], value[6:9], value[9:]))


IBAN_AL = iban("AL", "212110090000000235698741")
IBAN_LI = iban("LI", "0881000123456789X")
IBAN_RU = iban("RU", "04452560040702810412345678901")
CARD_MC2 = card("222112345678901")       # Mastercard 2-series
CARD_MIR = card("220012345678901")
CARD_TROY = card("979212345678901")
CARD_AMEX = card("37123456789012")

# Token-shaped strings in the published formats, filled with arbitrary characters. None is a real key.
SYN_PASSWORD = "S3cretPassw0rd"
STRIPE_KEY = "sk_live_" + "Zq7Wm2Lp9Xr4Tn6V"
GITLAB_TOKEN = "glpat-" + "Zq7Wm2Lp9Xr4Tn6Vb8Kc"
NPM_TOKEN = "npm_" + "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay2Bx4Cw"
HF_TOKEN = "hf_" + "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay2"
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc" + "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay2Bx4Cw6Dv8Eu0Ft2Ns4Mr6Qo8"
SENDGRID_KEY = "SG." + "Zq7Wm2Lp9Xr4Tn6Vb8Kc3J" + "." + "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay2Bx4Cw6Dv8E"
# Assembled at run time so that no complete webhook URL appears in the source (GitHub push protection
# would otherwise refuse the commit, synthetic or not).
SLACK_WEBHOOK = "https://hooks." + "slack.com/services/" + "/".join(("T0SYNTH01", "B0SYNTH01", "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5"))
SLACK_WEBHOOK_PLACEHOLDER = "https://hooks." + "slack.com/services/" + "/".join(("T00000000", "B00000000", "X" * 24))
TELEGRAM_TOKEN = "987654321:AA" + "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay2B"
AGE_KEY = "AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2
AWS_SECRET = "Zq7Wm2Lp9Xr4Tn6Vb8Kc/Jd5Hf1Gs0Ay2Bx4Cw+D"     # 40 characters
AZURE_KEY = "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay2Bx4Cw6Dv8Eu0Ft+Ns/Mr1Qo3Pi5Oh7Ug9Yf2Re4Wd6Sc8Tb0Va1Ab=="
BEARER_TOKEN = "Zq7Wm2Lp9Xr4Tn6Vb8Kc3Jd5Hf1Gs0Ay"
