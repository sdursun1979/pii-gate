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


class NationalIdEngineTests(unittest.TestCase):
    def test_new_rules_block_by_default_and_can_be_turned_off(self):
        from pii_gate.config import parse
        from pii_gate.engine import Engine
        text = f"dni {syn.DNI_A} cf {syn.CF_A} bsn {syn.BSN_A} pesel {syn.PESEL_A} personnummer {syn.PNR_A}"
        rep = Engine().scan_text(text)
        self.assertEqual(sorted(rep.counts()), ["es-dni", "it-cf", "nl-bsn", "pl-pesel", "se-personnummer"])
        off = parse({"rules": {"es-dni": "off", "it-cf": "off", "nl-bsn": "warn", "pl-pesel": "off", "se-personnummer": "off"}})
        rep = Engine(off).scan_text(text)
        self.assertFalse(rep.blocked)
        self.assertEqual([f.rule for f in rep.warnings], ["nl-bsn"])

    def test_sql_gate_knows_the_new_id_columns(self):
        from pii_gate.engine import Engine
        for col in ("dni", "nie", "nif", "codice_fiscale", "bsn", "pesel", "personnummer", "samordningsnummer"):
            rep = Engine().scan_text(f"SELECT {col} FROM orders")
            self.assertEqual(list(rep.counts()), ["sql-pii"], col)


class MaskTests(unittest.TestCase):
    def test_mask_never_leaks(self):
        self.assertEqual(d.mask("  secretvalue "), "s***")
        self.assertEqual(d.mask(""), "***")


if __name__ == "__main__":
    unittest.main()
