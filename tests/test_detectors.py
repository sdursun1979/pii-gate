import time
import unittest

from pii_gate import detectors as d

import _synthetic as syn


def rules(findings):
    return [f.rule for f in findings]


class TcknTests(unittest.TestCase):
    def test_valid_number_is_found(self):
        found = list(d.find_tckn(f"customer {syn.TCKN_A} called"))
        self.assertEqual(rules(found), ["tckn"])
        self.assertNotIn(syn.TCKN_A, found[0].sample)
        self.assertEqual(found[0].sample, syn.TCKN_A[0] + "***")

    def test_bad_checksum_is_ignored(self):
        broken = syn.TCKN_A[:-1] + str((int(syn.TCKN_A[-1]) + 1) % 10)
        self.assertEqual(list(d.find_tckn(broken)), [])

    def test_leading_zero_and_embedded_digits_are_ignored(self):
        self.assertEqual(list(d.find_tckn("0" + syn.TCKN_A[1:])), [])
        self.assertEqual(list(d.find_tckn("9" + syn.TCKN_A)), [])  # 12 digits

    def test_well_known_test_number_and_allowlist(self):
        self.assertEqual(list(d.find_tckn("10000000146")), [])
        self.assertEqual(list(d.find_tckn(syn.TCKN_A, allow={syn.TCKN_A})), [])

    def test_two_numbers_two_findings(self):
        self.assertEqual(len(list(d.find_tckn(f"{syn.TCKN_A} and {syn.TCKN_B}"))), 2)


class IbanTests(unittest.TestCase):
    def test_compact_and_spaced(self):
        spaced = " ".join(syn.IBAN_TR[i:i + 4] for i in range(0, len(syn.IBAN_TR), 4))
        self.assertEqual(rules(d.find_iban("iban: " + syn.IBAN_TR)), ["iban"])
        self.assertEqual(rules(d.find_iban("iban: " + spaced)), ["iban"])
        self.assertEqual(rules(d.find_iban(syn.IBAN_GB)), ["iban"])

    def test_bad_check_digits(self):
        broken = syn.IBAN_TR[:2] + "00" + syn.IBAN_TR[4:]
        self.assertEqual(list(d.find_iban(broken)), [])

    def test_wrong_length_for_country(self):
        self.assertEqual(list(d.find_iban(syn.iban("TR", "000120091234567890123"))), [])

    def test_registry_examples_are_not_personal(self):
        self.assertEqual(list(d.find_iban("GB82 WEST 1234 5698 7654 32")), [])


class CardTests(unittest.TestCase):
    def test_luhn_valid_with_separators(self):
        self.assertEqual(rules(d.find_card(syn.CARD_VISA)), ["card"])
        grouped = " ".join(syn.CARD_VISA[i:i + 4] for i in range(0, 16, 4))
        self.assertEqual(rules(d.find_card(grouped)), ["card"])
        self.assertEqual(rules(d.find_card(syn.CARD_MC.replace(" ", "-"))), ["card"])

    def test_luhn_invalid_and_bad_prefix(self):
        broken = syn.CARD_VISA[:-1] + str((int(syn.CARD_VISA[-1]) + 1) % 10)
        self.assertEqual(list(d.find_card(broken)), [])
        self.assertEqual(list(d.find_card("1" + syn.CARD_VISA[1:])), [])

    def test_published_test_cards(self):
        self.assertEqual(list(d.find_card("4111 1111 1111 1111")), [])


class EmailTests(unittest.TestCase):
    def test_found_and_masked(self):
        found = list(d.find_email("mail ayse.k@somecompany.com.tr now"))
        self.assertEqual(rules(found), ["email"])
        self.assertEqual(found[0].sample, "a***")

    def test_reserved_and_allowed_domains(self):
        self.assertEqual(list(d.find_email("bob@example.com x@foo.test y@users.noreply.github.com")), [])
        self.assertEqual(list(d.find_email("ops@mycorp.io", allow_domains=["mycorp.io"])), [])


class PhoneTests(unittest.TestCase):
    def test_turkish_and_international(self):
        for text in ("+90 532 123 45 67", "0532 123 45 67", "5321234567", "+1 212 555 0199", "+44 20 7946 0958"):
            self.assertEqual(rules(d.find_phone(text)), ["phone"], text)

    def test_not_phones(self):
        for text in ("2024-10-23", "order 12345", "v1.2.3", "port 8080"):
            self.assertEqual(list(d.find_phone(text)), [], text)


class SecretTests(unittest.TestCase):
    def test_token_formats_block(self):
        for text in (syn.AWS_KEY, syn.OPENAI_KEY, syn.GITHUB_TOKEN, syn.PRIVATE_KEY):
            found = list(d.find_secrets(text))
            self.assertEqual(rules(found), ["secret"], text)
            self.assertTrue(found[0].sample.endswith("***"))

    def test_documentation_placeholders_pass(self):
        self.assertEqual(list(d.find_secrets("AKIAIOSFODNN7EXAMPLE sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx")), [])

    def test_clear_text_assignment_is_a_warning_rule(self):
        self.assertEqual(rules(d.find_secrets('password = "hunter2hunter2"')), ["secret-assign"])
        self.assertEqual(rules(d.find_secrets("API_KEY=9f8e7d6c5b4a3f2e1d")), ["secret-assign"])

    def test_code_and_placeholders_are_not_assignments(self):
        for text in ('password = os.environ["PW"]', "password = input()", "api_key: <your-key>",
                     "password: ${DB_PASSWORD}", "secret = getenv('S')"):
            self.assertEqual(list(d.find_secrets(text)), [], text)


class SpanishIdTests(unittest.TestCase):
    def test_dni_and_nie_found(self):
        for text in (f"dni {syn.DNI_A}", f"{syn.DNI_A[:8]}-{syn.DNI_A[8]}", f"nie: {syn.NIE_A}"):
            found = list(d.find_es_id(text))
            self.assertEqual(rules(found), ["es-dni"], text)
            self.assertTrue(found[0].sample.endswith("***"))

    def test_wrong_letter_embedded_and_trivial_are_ignored(self):
        wrong = syn.DNI_A[:8] + ("A" if syn.DNI_A[8] != "A" else "B")
        for text in (wrong, "A" + syn.DNI_A, syn.DNI_A + "9", "00000000T", syn.DNI_A.lower()):
            self.assertEqual(list(d.find_es_id(text)), [], text)

    def test_published_examples_and_allowlist(self):
        self.assertEqual(list(d.find_es_id("12345678Z X1234567L")), [])
        self.assertEqual(list(d.find_es_id(syn.DNI_A, allow={syn.DNI_A})), [])


class ItalianCodiceFiscaleTests(unittest.TestCase):
    def test_algorithm_matches_published_examples(self):
        self.assertTrue(d.it_cf_valid("RSSMRA85T10A562S"))
        self.assertTrue(d.it_cf_valid("MRTMTT25D09F205Z"))

    def test_found_including_omocodia(self):
        self.assertEqual(rules(d.find_it_cf(f"cf: {syn.CF_A}")), ["it-cf"])
        self.assertEqual(rules(d.find_it_cf(syn.CF_OMOCODIA)), ["it-cf"])

    def test_bad_check_bad_day_and_textbook_value_are_ignored(self):
        wrong = syn.CF_A[:15] + ("A" if syn.CF_A[15] != "A" else "B")
        for text in (wrong, syn.CF_BAD_DAY, "RSSMRA85T10A562S", "X" + syn.CF_A):
            self.assertEqual(list(d.find_it_cf(text)), [], text)


class DutchBsnTests(unittest.TestCase):
    def test_algorithm_matches_published_example(self):
        self.assertTrue(d.nl_bsn_valid("123456782"))

    def test_found_only_next_to_its_label(self):
        for text in (f"BSN: {syn.BSN_A}", f"burgerservicenummer {syn.BSN_A}", f'{{"bsn": "{syn.BSN_A}"}}'):
            self.assertEqual(rules(d.find_nl_bsn(text)), ["nl-bsn"], text)
        for text in (syn.BSN_A, f"order {syn.BSN_A} shipped", f"bsn" + " " * 50 + syn.BSN_A):
            self.assertEqual(list(d.find_nl_bsn(text)), [], text)

    def test_bad_check_and_examples_are_ignored(self):
        broken = syn.BSN_A[:-1] + str((int(syn.BSN_A[-1]) + 1) % 10)
        for text in (f"bsn {broken}", "bsn 123456782", "bsn 111111111"):
            self.assertEqual(list(d.find_nl_bsn(text)), [], text)


class PolishPeselTests(unittest.TestCase):
    def test_algorithm_matches_published_example(self):
        self.assertTrue(d.pl_pesel_valid("44051401359"))

    def test_found_only_next_to_its_label(self):
        self.assertEqual(rules(d.find_pl_pesel(f"PESEL: {syn.PESEL_A}")), ["pl-pesel"])
        self.assertEqual(list(d.find_pl_pesel(syn.PESEL_A)), [])

    def test_bad_date_bad_check_and_turkish_phone_are_ignored(self):
        broken = syn.PESEL_A[:-1] + str((int(syn.PESEL_A[-1]) + 1) % 10)
        for text in (f"pesel {syn.PESEL_BAD_DATE}", f"pesel {broken}", "pesel 44051401359", "tel 05321234567"):
            self.assertEqual(list(d.find_pl_pesel(text)), [], text)


class SwedishPersonnummerTests(unittest.TestCase):
    def test_found_next_to_its_label(self):
        self.assertEqual(rules(d.find_se_personnummer(f"personnummer: {syn.PNR_A}")), ["se-personnummer"])
        self.assertEqual(rules(d.find_se_personnummer(f"Personnummer {syn.PNR_A.replace('-', '')}")),
                         ["se-personnummer"])
        self.assertEqual(list(d.find_se_personnummer(syn.PNR_A)), [])

    def test_coordination_number_adds_sixty_to_the_day(self):
        self.assertEqual(rules(d.find_se_personnummer(f"samordningsnummer {syn.SAMORDNING_A}")),
                         ["se-personnummer"])
        self.assertEqual(syn.SAMORDNING_A[4:6], "61")

    def test_plus_separator_means_over_one_hundred(self):
        self.assertEqual(rules(d.find_se_personnummer(f"personnummer {syn.PNR_PLUS}")), ["se-personnummer"])
        # 29 February 1900 does not exist, 2000 does: valid with "-" only
        leap = syn.personnummer("000229123")
        self.assertTrue(d.se_personnummer_valid(leap, "-"))
        self.assertFalse(d.se_personnummer_valid(leap, "+"))

    def test_bad_luhn_is_ignored(self):
        broken = syn.PNR_A[:-1] + str((int(syn.PNR_A[-1]) + 1) % 10)
        self.assertEqual(list(d.find_se_personnummer(f"personnummer {broken}")), [])

    def test_missing_label_is_ignored(self):
        self.assertEqual(list(d.find_se_personnummer(f"order {syn.PNR_A} shipped")), [])

    def test_invalid_date_is_ignored(self):
        self.assertEqual(list(d.find_se_personnummer(f"personnummer {syn.PNR_BAD_DATE}")), [])
        day_zero = syn.personnummer("900100123")
        self.assertEqual(list(d.find_se_personnummer(f"personnummer {day_zero}")), [])
        day_sixty = syn.personnummer("900160123")
        self.assertEqual(list(d.find_se_personnummer(f"samordningsnummer {day_sixty}")), [])

    def test_twelve_digit_form_is_not_matched(self):
        self.assertEqual(list(d.find_se_personnummer(f"personnummer 19{syn.PNR_A}")), [])

    def test_engine_and_sql_gate(self):
        from pii_gate.engine import Engine
        rep = Engine().scan_text(f"personnummer {syn.PNR_A}")
        self.assertEqual(list(rep.counts()), ["se-personnummer"])
        self.assertNotIn(syn.PNR_A, rep.blocking[0].sample)
        for col in ("personnummer", "samordningsnummer"):
            self.assertEqual(list(Engine().scan_text(f"SELECT {col} FROM orders").counts()), ["sql-pii"], col)


class BelgianRegisterNumberTests(unittest.TestCase):
    def test_algorithm_matches_published_examples(self):
        # The worked examples on the French Wikipedia page "Numéro de registre national".
        self.assertTrue(d.be_rrn_valid("85073003328"))   # born 1985: 97 - 850730033 mod 97
        self.assertTrue(d.be_rrn_valid("17073003384"))   # born after 1999: 97 - 2170730033 mod 97

    def test_found_only_next_to_its_label(self):
        for label in ("rijksregisternummer", "Numéro de registre national", "NISS", "INSZ nr",
                      "national register number"):
            self.assertEqual(rules(d.find_be_rrn(f"{label}: {syn.RRN_A}")), ["be-rrn"], label)
        self.assertEqual(list(d.find_be_rrn(syn.RRN_A)), [])
        self.assertEqual(list(d.find_be_rrn(f"order {syn.RRN_A} shipped")), [])

    def test_written_forms_born_after_1999_and_bis_numbers(self):
        for value in (syn.RRN_DOTTED, syn.RRN_2000, syn.RRN_BIS):
            self.assertEqual(rules(d.find_be_rrn(f"NISS {value}")), ["be-rrn"], value)

    def test_bad_check_bad_date_and_turkish_phone_are_ignored(self):
        broken = syn.RRN_A[:-1] + str((int(syn.RRN_A[-1]) + 1) % 10)
        for text in (f"NISS {broken}", f"NISS {syn.RRN_BAD_DATE}", "NISS 05321234567", "NISS 00000000000"):
            self.assertEqual(list(d.find_be_rrn(text)), [], text)

    def test_blocks_by_default_masks_the_value_and_is_a_sql_column(self):
        from pii_gate.engine import Engine
        rep = Engine().scan_text(f"rijksregisternummer {syn.RRN_DOTTED}")
        self.assertEqual(list(rep.counts()), ["be-rrn"])
        self.assertNotIn(syn.RRN_DOTTED, rep.blocking[0].sample)
        for col in ("rijksregisternummer", "niss", "insz"):
            self.assertEqual(list(Engine().scan_text(f"SELECT {col} FROM orders").counts()), ["sql-pii"], col)

    def test_is_linear(self):
        t0 = time.perf_counter()
        list(d.find_be_rrn("NISS " + "12.34.56-" * 100000))
        list(d.find_be_rrn("NISS " + "1" * 1_000_000))
        self.assertLess(time.perf_counter() - t0, 1.0)


class NationalIdEngineTests(unittest.TestCase):
    def test_new_rules_block_by_default_and_can_be_turned_off(self):
        from pii_gate.config import parse
        from pii_gate.engine import Engine
        text = f"dni {syn.DNI_A} cf {syn.CF_A} bsn {syn.BSN_A} pesel {syn.PESEL_A}"
        rep = Engine().scan_text(text)
        self.assertEqual(sorted(rep.counts()), ["es-dni", "it-cf", "nl-bsn", "pl-pesel"])
        off = parse({"rules": {"es-dni": "off", "it-cf": "off", "nl-bsn": "warn", "pl-pesel": "off"}})
        rep = Engine(off).scan_text(text)
        self.assertFalse(rep.blocked)
        self.assertEqual([f.rule for f in rep.warnings], ["nl-bsn"])

    def test_sql_gate_knows_the_new_id_columns(self):
        from pii_gate.engine import Engine
        for col in ("dni", "nie", "nif", "codice_fiscale", "bsn", "pesel"):
            rep = Engine().scan_text(f"SELECT {col} FROM orders")
            self.assertEqual(list(rep.counts()), ["sql-pii"], col)

class NormalisationTests(unittest.TestCase):
    def test_invisible_characters_do_not_split_a_value(self):
        for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"):
            text = syn.TCKN_A[:5] + ch + syn.TCKN_A[5:]
            found = list(d.find_pii(text))
            self.assertEqual(rules(found), ["tckn"], repr(ch))
            self.assertEqual(found[0].sample, syn.TCKN_A[0] + "***")
        self.assertEqual(rules(d.find_pii(syn.IBAN_TR[:10] + "\u200b" + syn.IBAN_TR[10:])), ["iban"])
        self.assertEqual(rules(d.find_secrets(syn.GITHUB_TOKEN[:8] + "\u200b" + syn.GITHUB_TOKEN[8:])), ["secret"])

    def test_no_break_space_and_fullwidth_digits(self):
        self.assertEqual(rules(d.find_pii(syn.grouped(syn.CARD_VISA, sep="\u00a0"))), ["card"])
        self.assertEqual(rules(d.find_pii(syn.fullwidth(syn.TCKN_A))), ["tckn"])
        self.assertEqual(rules(d.find_pii(syn.fullwidth(syn.CARD_VISA))), ["card"])
        self.assertEqual(rules(d.find_pii(syn.fullwidth(syn.IBAN_TR))), ["iban"])

    def test_offsets_refer_to_the_original_text(self):
        zw = chr(0x200b)
        text = "a" + zw + "b " + syn.TCKN_A[:5] + zw + syn.TCKN_A[5:] + " " + zw + syn.CARD_VISA
        found = list(d.find_pii(text))
        self.assertEqual([text[f.start:f.end] for f in found],
                         [syn.TCKN_A[:5] + zw + syn.TCKN_A[5:], syn.CARD_VISA])
        text = zw + "password = " + zw + syn.SYN_PASSWORD
        self.assertEqual([text[f.start:f.end] for f in d.find_secrets(text)], [syn.SYN_PASSWORD])

    def test_plain_text_is_untouched(self):
        self.assertEqual(d.normalise("abc 123"), "abc 123")
        self.assertEqual(d.normalise("a\u00a0b\u200bc"), "a bc")


class GroupedTcknTests(unittest.TestCase):
    def test_space_and_dot_groups(self):
        for sep in (" ", "."):
            found = list(d.find_tckn("tc: " + syn.tckn_grouped(syn.TCKN_A, sep)))
            self.assertEqual(rules(found), ["tckn"], sep)
            self.assertEqual(found[0].sample, syn.TCKN_A[0] + "***")

    def test_phones_mixed_separators_and_longer_runs_are_ignored(self):
        broken = syn.TCKN_A[:-1] + str((int(syn.TCKN_A[-1]) + 1) % 10)
        mixed = syn.TCKN_A[:3] + " " + syn.TCKN_A[3:6] + "." + syn.TCKN_A[6:9] + " " + syn.TCKN_A[9:]
        for text in ("+90 532 123 45 67", "0532 123 45 67", "532 123 45 67", "90 532 123 45 67", mixed,
                     "1 " + syn.tckn_grouped(syn.TCKN_A), syn.tckn_grouped(syn.TCKN_A) + " 12",
                     syn.tckn_grouped(broken), syn.tckn_grouped("10000000146")):
            self.assertEqual(list(d.find_tckn(text)), [], text)


class IbanFormatTests(unittest.TestCase):
    def test_case_hyphens_and_glued_label(self):
        for text in (syn.IBAN_TR.lower(), "IBAN" + syn.IBAN_TR, syn.grouped(syn.IBAN_TR, sep="-"),
                     syn.IBAN_TR[:2].lower() + syn.IBAN_TR[2:]):
            found = list(d.find_iban(text))
            self.assertEqual(rules(found), ["iban"], text)
            self.assertEqual(found[0].sample, "T***")

    def test_trailing_text_does_not_hide_the_iban(self):
        spaced = syn.grouped(syn.IBAN_TR)
        for text in (spaced + " TL", spaced + " USD 1500", spaced + " 2024", spaced + "\n2024",
                     syn.IBAN_TR + " 15000 TL", syn.IBAN_TR + " X"):
            self.assertEqual(rules(d.find_iban(text)), ["iban"], text)

    def test_two_ibans_in_a_row(self):
        self.assertEqual(rules(d.find_iban(syn.IBAN_TR + " " + syn.IBAN_GB)), ["iban", "iban"])
        spaced = syn.grouped(syn.IBAN_TR)
        self.assertEqual(rules(d.find_iban(spaced + " " + spaced)), ["iban", "iban"])

    def test_registry_countries(self):
        for value in (syn.IBAN_AL, syn.IBAN_LI, syn.IBAN_RU):
            self.assertEqual(rules(d.find_iban(value)), ["iban"], value)
        self.assertEqual(len(d.IBAN_LENGTHS), 88)
        for cc, n in {"AL": 28, "AD": 24, "BA": 20, "BR": 29, "BY": 28, "CR": 22, "DO": 28, "FO": 18, "GI": 23,
                      "GL": 18, "GT": 28, "IQ": 23, "JO": 30, "LB": 28, "LC": 32, "LI": 21, "LY": 25, "MC": 27,
                      "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MU": 30, "PK": 24, "PS": 29, "RS": 22, "SC": 31,
                      "SI": 19, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "UA": 29, "VA": 22, "VG": 24,
                      "XK": 20}.items():
            self.assertEqual(d.IBAN_LENGTHS[cc], n, cc)

    def test_near_misses(self):
        for text in (syn.iban("XX", "0881000123456789012"),          # not an IBAN country, mod 97 fine
                     syn.IBAN_TR + "1", "x" + syn.IBAN_TR,             # glued to more characters
                     "de12" + "a" * 36,                                # hash-like run, cut inside a group
                     syn.IBAN_TR[:2] + "00" + syn.IBAN_TR[4:]):
            self.assertEqual(list(d.find_iban(text)), [], text)


class CardFormatTests(unittest.TestCase):
    def test_dots_expiry_and_cvv(self):
        spaced = syn.grouped(syn.CARD_VISA)
        for text in (syn.grouped(syn.CARD_VISA, sep="."), spaced + " 12/26", spaced + " 1", syn.CARD_VISA + " 123",
                     syn.CARD_VISA + "-123", "kart " + spaced + " son kullanma 12/26"):
            found = list(d.find_card(text))
            self.assertEqual(rules(found), ["card"], text)
            self.assertEqual(found[0].sample, "4***")

    def test_more_issuer_ranges(self):
        for value in (syn.CARD_MC2, syn.CARD_MIR, syn.CARD_TROY, syn.CARD_AMEX, syn.card("272012345678901")):
            self.assertEqual(rules(d.find_card(value)), ["card"], value)

    def test_two_cards(self):
        self.assertEqual(rules(d.find_card(syn.CARD_VISA + " " + syn.CARD_MC)), ["card", "card"])

    def test_near_misses(self):
        for text in (syn.card("979112345678901"), syn.card("220512345678901"), syn.card("272112345678901"),
                     syn.card("153957876362148"), "4111 1111 1111 1111 1", "1729770000" + syn.CARD_VISA,
                     " ".join(syn.CARD_VISA + "121")):           # single digits: no shorter-run retry
            self.assertEqual(list(d.find_card(text)), [], text)


class SecretFormatTests(unittest.TestCase):
    TOKENS = {
        "Stripe key": syn.STRIPE_KEY, "GitLab token": syn.GITLAB_TOKEN, "npm token": syn.NPM_TOKEN,
        "Hugging Face token": syn.HF_TOKEN, "PyPI token": syn.PYPI_TOKEN, "SendGrid key": syn.SENDGRID_KEY,
        "Slack webhook": syn.SLACK_WEBHOOK,
        "Telegram bot token": syn.TELEGRAM_TOKEN, "age secret key": syn.AGE_KEY,
        "AWS secret key": "aws_secret_access_key = " + syn.AWS_SECRET,
        "Azure storage key": "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + syn.AZURE_KEY + ";",
        "credentials in URL": "postgres://app:" + syn.SYN_PASSWORD + "@db.internal:5432/prod",
        "Authorization header": "curl -H 'Authorization: Bearer " + syn.BEARER_TOKEN + "' https://api.internal",
        "private key": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    }

    def test_new_formats_block_once_and_never_leak(self):
        for label, text in self.TOKENS.items():
            found = list(d.find_secrets(text))
            self.assertEqual([(f.rule, f.note) for f in found], [("secret", label)], text)
            self.assertTrue(found[0].sample.endswith("***"))
            self.assertEqual(len(found[0].sample), 4)

    def test_more_url_and_header_forms(self):
        for text in ("redis://:" + syn.SYN_PASSWORD + "@redis:6379/0",
                     "mongodb+srv://app:" + syn.SYN_PASSWORD + "@cluster.internal/db",
                     "AWS_SECRET_ACCESS_KEY=" + syn.AWS_SECRET,
                     '{"Authorization": "Basic ' + syn.BEARER_TOKEN + '"}',
                     "https://api.telegram.org/bot" + syn.TELEGRAM_TOKEN + "/getMe",
                     "rk_test_" + syn.STRIPE_KEY[8:]):
            self.assertEqual(rules(d.find_secrets(text)), ["secret"], text)

    def test_near_misses_stay_clean(self):
        for text in ("https://github.com/org/repo", "postgres://localhost/db", "https://user@host/", "file:///C:/x",
                     "http://example.com:8080/path", "https://x:y@h", "postgres://user:password@localhost/db",
                     "postgres://user:${DB_PASS}@localhost/db", "Authorization: Bearer <token>",
                     "Authorization: Bearer $TOKEN", 'headers = {"Authorization": f"Bearer {token}"}',
                     "Authorization: Bearer YOUR_TOKEN_HERE_123456", "git@github.com:org/repo.git",
                     "pk_live_" + syn.STRIPE_KEY[8:], "npm_config_registry=https://registry.npmjs.org",
                     syn.SLACK_WEBHOOK_PLACEHOLDER,
                     "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                     "123" + syn.TELEGRAM_TOKEN):                       # 12-digit id: not a bot id
            self.assertEqual(list(d.find_secrets(text)), [], text)

    def test_jwt_is_not_excused_by_placeholder_words(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzeW50aGV0aWMifQ.xxx" + "Zq7Wm2Lp9Xr4Tn6V"
        self.assertEqual(rules(d.find_secrets(jwt)), ["secret"])


class AssignmentTests(unittest.TestCase):
    PW = syn.SYN_PASSWORD

    def test_config_shapes_are_caught(self):
        pw = self.PW
        for text in ('{"password": "%s"}' % pw, "POSTGRES_PASSWORD=" + pw, "export DB_PASSWORD=" + pw,
                     "ADMIN_PASSWORD: " + pw, "DB_PASS=" + pw, "SECRET_KEY=" + pw, "SECRET_KEY_BASE=" + pw,
                     "secretKey: " + pw, "private_key=" + pw, 'password := "%s"' % pw, "'password' => '%s'" % pw,
                     "Password=%s;TrustServerCertificate=true" % pw, "client_secret: " + pw, "passphrase = " + pw,
                     "password2 = " + pw, 'password = "' + pw):
            found = list(d.find_secrets(text))
            self.assertEqual(rules(found), ["secret-assign"], text)
            self.assertEqual(found[0].sample, pw[0] + "***")
        self.assertEqual(rules(d.find_secrets('password="S3cret Passw0rd"')), ["secret-assign"])

    def test_passwords_with_code_like_characters_are_caught(self):
        for value in ("Pa$$w0rd!longer", "trueLove1234!", "NoneShallPass1!", "S3cret(Passw0rd)", "100%Secure2024"):
            self.assertEqual(rules(d.find_secrets("password = '%s'" % value)), ["secret-assign"], value)
        self.assertEqual(rules(d.find_secrets("DB_PASSWORD=mypassword123")), ["secret-assign"])

    def test_code_and_references_stay_clean(self):
        for text in ("password = request.form['password']", "password = self._password", "password = password_hash",
                     "password: Optional[str] = None", "password: '**********'", 'password = os.environ["PW"]',
                     "password = os.getenv('PW')", "password: ${DB_PASSWORD}", "password = '$(cat /run/secrets/db)'",
                     "password = '%(password)s'", "password = $DB_PASSWORD", "password = secrets.token_hex(16)",
                     "password = hashlib.sha256(raw).hexdigest()", "password = getpass.getpass()",
                     "api_key: process.env.API_KEY", "password = user.password", "password = DB_PASSWORD",
                     "password = hashedPassword", 'password = "{password}"', "PWD=/home/user/project",
                     "POSTGRES_PASSWORD_FILE=/run/secrets/pg", "password = 'changeme123'"):
            self.assertEqual(list(d.find_secrets(text)), [], text)

    def test_names_that_only_contain_a_keyword(self):
        for text in ("token_count = 12345678", "tokenizer = AutoTokenizer", "keyboard_shortcuts = settings",
                     "password_hash = abcdefghijkl", "password_reset_url = https://site.io/reset",
                     "secretary_name = Alice_Wonderland", "passport_no = 12345678", "bypass = something_long",
                     "access_token_ttl = 86400000", "monkey_key = 12345678", "session_token = abcdefghijkl"):
            self.assertEqual(list(d.find_secrets(text)), [], text)

    def test_reported_once_when_a_token_pattern_matches(self):
        found = list(d.find_secrets("aws_secret_access_key = " + syn.AWS_SECRET))
        self.assertEqual([f.note for f in found], ["AWS secret key"])


class EmailFormatTests(unittest.TestCase):
    def test_sentence_final_dot(self):
        for text in ("write to ayse.k@somecompany.com.tr.", "ayse.k@somecompany.com.tr. Next", "mail ayse@corp.io: hi"):
            found = list(d.find_email(text))
            self.assertEqual(rules(found), ["email"], text)
            self.assertEqual(found[0].sample, "a***")

    def test_ssh_addresses_are_not_mailboxes(self):
        for text in ("git@github.com:org/repo.git", "deploy@build.corp.io:/var/www", "ssh git@corp.io",
                     "git clone git@gitlab.corp.io:team/app.git"):
            self.assertEqual(list(d.find_email(text)), [], text)


class SpanishIdFormatTests(unittest.TestCase):
    def test_separators_after_nie_letter_and_before_check_letter(self):
        n = syn.NIE_A
        for text in (f"{n[0]}-{n[1:8]}-{n[8]}", f"{n[0]} {n[1:8]} {n[8]}", f"{syn.DNI_A[:8]} {syn.DNI_A[8]}"):
            found = list(d.find_es_id(text))
            self.assertEqual(rules(found), ["es-dni"], text)
            self.assertEqual(found[0].sample, text[0] + "***")

    def test_wrong_letter_with_separator(self):
        wrong = "A" if syn.DNI_A[8] != "A" else "B"
        self.assertEqual(list(d.find_es_id(f"{syn.DNI_A[:8]} {wrong}")), [])
        self.assertEqual(list(d.find_es_id("12345678-Z")), [])


class MaskTests(unittest.TestCase):
    def test_mask_never_leaks(self):
        self.assertEqual(d.mask("  secretvalue "), "s***")
        self.assertEqual(d.mask(""), "***")


if __name__ == "__main__":
    unittest.main()
