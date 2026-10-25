import time
import unittest

from pii_gate import sqlgate
from pii_gate.config import parse
from pii_gate.engine import Engine


def run(sql, cfg=None):
    rep = Engine(cfg).scan_text(sql)
    return sorted({f.rule for f in rep.blocking}), sorted({f.rule for f in rep.warnings})


class CoreColumnTests(unittest.TestCase):
    def test_core_column_blocks_anywhere(self):
        self.assertEqual(run("SELECT national_id FROM customers"), (["sql-pii"], []))
        self.assertEqual(run("select c.birth_date, c.city from dbo.customers c"), (["sql-pii"], []))
        self.assertEqual(run("SELECT [Birth_Date] FROM [dbo].[Orders]"), (["sql-pii"], []))

    def test_partial_substring_is_fine(self):
        self.assertEqual(run("SELECT customer_count, dob_flag FROM stats"), ([], []))


class ContextColumnTests(unittest.TestCase):
    def test_outside_person_table_is_a_warning(self):
        self.assertEqual(run("SELECT name, email, phone FROM suppliers"), ([], ["sql-pii-context"]))

    def test_inside_person_table_blocks(self):
        self.assertEqual(run("SELECT name, email FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT p.first_name FROM dbo.patients p JOIN visits v ON v.pid = p.id"), (["sql-pii"], []))
        self.assertEqual(run("SELECT e.email FROM employees e"), (["sql-pii"], []))


class StarTests(unittest.TestCase):
    def test_star_on_person_table(self):
        self.assertEqual(run("SELECT * FROM patients"), (["sql-star"], []))
        self.assertEqual(run("SELECT p.* FROM patients p"), (["sql-star"], []))

    def test_star_elsewhere(self):
        self.assertEqual(run("SELECT * FROM orders"), ([], []))


class TableStatementTests(unittest.TestCase):
    def test_table_statement_on_a_person_table(self):
        for sql in ("TABLE patients;", "table patients", "TABLE ONLY patients;", "TABLE public.patients ORDER BY id LIMIT 5;",
                    'psql -c "TABLE patients"', "psql -c 'TABLE patients'", "SELECT id FROM visits UNION TABLE patients;",
                    "SELECT * FROM (TABLE patients) p;", "-- dump\nTABLE patients;", "x = 1; TABLE users;"):
            self.assertEqual(run(sql), (["sql-star"], []), sql)
            self.assertTrue(sqlgate.looks_like_sql(sql), sql)

    def test_ddl_other_tables_and_prose(self):
        for sql in ("TABLE orders;", "CREATE TABLE patients (id int);", "CREATE TEMP TABLE patients (id int);",
                    "DROP TABLE patients;", "DROP TABLE IF EXISTS patients;", "DROP\nTABLE patients;",
                    "ALTER TABLE patients ADD x int;", "LOCK TABLE patients;", "LOCK TABLE ONLY patients;",
                    "TRUNCATE TABLE patients;", "RENAME TABLE patients TO p2;", "INSERT INTO archive TABLE patients;",
                    "Look at the table patients;", "The table users has many rows.", "Table users\nholds people."):
            self.assertEqual(run(sql), ([], []), sql)

    def test_is_linear(self):
        t0 = time.perf_counter()
        for text in ("TABLE " * 100000, "table patients " * 50000, "table patients;" * 20000):
            list(sqlgate.find_sql(text))
        self.assertLess(time.perf_counter() - t0, 1.0)


class WrapperTests(unittest.TestCase):
    def test_non_revealing_wrappers_pass(self):
        sql = ("SELECT COUNT(national_id), COUNT(DISTINCT email), LEN(phone), LEFT(first_name, 1), "
               "SUBSTRING(last_name, 1, 1), YEAR(birth_date), DATEPART(year, birth_date), "
               "phone IS NOT NULL FROM patients WHERE phone IS NOT NULL GROUP BY YEAR(birth_date)")
        self.assertEqual(run(sql), ([], []))

    def test_revealing_wrappers_block(self):
        self.assertEqual(run("SELECT SUBSTRING(national_id, 1, 3) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT UPPER(email) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT MONTH(birth_date), DAY(birth_date) FROM patients"), (["sql-pii"], []))


class ParsingTests(unittest.TestCase):
    def test_comments_and_strings_are_ignored(self):
        self.assertEqual(run("SELECT id -- national_id\nFROM visits"), ([], []))
        self.assertEqual(run("SELECT 'national_id' AS label FROM visits"), ([], []))

    def test_subquery(self):
        self.assertEqual(run("SELECT v.id FROM visits v WHERE v.pid IN (SELECT national_id FROM patients)"),
                         (["sql-pii"], []))

    def test_prose_with_select_from(self):
        self.assertEqual(run("please select from the menu"), ([], []))
        self.assertEqual(run("no sql here, just email text"), ([], []))


class ConfigTests(unittest.TestCase):
    def test_ignore_extra_columns_and_tables(self):
        cfg = parse({"sql": {"ignore_columns": ["name"], "extra_pii_columns": ["protocol_no"],
                             "extra_person_tables": ["donor"]}})
        self.assertEqual(run("SELECT name FROM suppliers", cfg), ([], []))
        self.assertEqual(run("SELECT protocol_no FROM visits", cfg), (["sql-pii"], []))
        self.assertEqual(run("SELECT email FROM donors", cfg), (["sql-pii"], []))

    def test_rule_levels(self):
        cfg = parse({"rules": {"sql-pii": "warn", "sql-pii-context": "block"}})
        self.assertEqual(run("SELECT national_id FROM customers", cfg), ([], ["sql-pii"]))
        self.assertEqual(run("SELECT phone FROM suppliers", cfg), (["sql-pii-context"], []))
        cfg = parse({"rules": {"sql-pii": "off", "sql-star": "off"}})
        self.assertEqual(run("SELECT *, national_id FROM patients", cfg), ([], []))

class EmbeddedSqlTests(unittest.TestCase):
    def test_sql_inside_single_quoted_literals_is_scanned(self):
        self.assertEqual(run("psql -c 'SELECT national_id FROM patients'"), (["sql-pii"], []))
        self.assertEqual(run("EXEC sp_executesql N'SELECT national_id FROM patients'"), (["sql-pii"], []))
        self.assertEqual(run("SELECT x FROM t WHERE a = 'it''s' AND q = 'SELECT national_id FROM patients'"),
                         (["sql-pii"], []))

    def test_plain_literals_stay_blank(self):
        self.assertEqual(run("SELECT 'national_id' AS label FROM visits"), ([], []))
        self.assertEqual(run("EXEC sp_executesql N'SELECT ''national_id'' AS label FROM visits'"), ([], []))

    def test_double_dash_flags_are_not_comments(self):
        self.assertEqual(run('psql --host=db -c "SELECT national_id FROM patients"'), (["sql-pii"], []))
        self.assertEqual(run('mysql --execute="SELECT national_id FROM patients" db'), (["sql-pii"], []))
        self.assertEqual(run("SELECT id --national_id\nFROM visits"), (["sql-pii"], []))   # fail closed
        self.assertEqual(run("SELECT id -- national_id\nFROM visits"), ([], []))
        self.assertEqual(run("SELECT id --\nFROM visits"), ([], []))

    def test_unclosed_block_comment_is_linear(self):
        t0 = time.perf_counter()
        self.assertEqual(run("select a from b " + "/* " * 20000), ([], []))
        self.assertEqual(run("SELECT national_id /* note */ FROM patients /* unclosed"), (["sql-pii"], []))
        self.assertLess(time.perf_counter() - t0, 1.0)


class FromInsideFunctionTests(unittest.TestCase):
    def test_extract_trim_substring(self):
        self.assertEqual(run("SELECT EXTRACT(YEAR FROM birth_date) FROM patients"), ([], []))
        self.assertEqual(run("SELECT EXTRACT(YEAR FROM birth_date), national_id FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT EXTRACT(DAY FROM birth_date) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT TRIM(LEADING '0' FROM national_id) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT SUBSTRING(national_id FROM 1 FOR 3) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT COUNT(*), EXTRACT(MONTH FROM visit_date), p.national_id FROM patients p"),
                         (["sql-pii"], []))

    def test_one_level_of_nested_parentheses(self):
        for sql in ("SELECT SUBSTRING(COALESCE(code, 'x') FROM 1 FOR 3), national_id FROM patients",
                    "SELECT TRIM(LEADING '0' FROM COALESCE(code, '')), national_id FROM patients",
                    "SELECT EXTRACT(YEAR FROM COALESCE(visit_date, NOW())), national_id FROM patients"):
            self.assertEqual(run(sql), (["sql-pii"], []), sql)
        self.assertEqual(run("SELECT EXTRACT(YEAR FROM COALESCE(visit_date, NOW())), id FROM visits"), ([], []))
        self.assertEqual(run("SELECT SUBSTRING(COALESCE(code, 'x') FROM 1 FOR 3) FROM visits"), ([], []))

    def test_is_linear(self):
        t0 = time.perf_counter()
        for text in ("select " + "SUBSTRING(COALESCE(" * 20000 + " from t", "select substring(" + "(x)" * 60000 + " from t",
                     "select extract(" + "x " * 100000 + " from t"):
            list(sqlgate.find_sql(text))
        self.assertLess(time.perf_counter() - t0, 1.0)


class IdentifierPartTests(unittest.TestCase):
    def test_camel_case_brackets_and_turkish_letters(self):
        for col in ("nationalIdNumber", "TCKimlikNo", "[TC Kimlik No]", '"National Id"', "`Birth Date`",
                    "[Do\u011fum Tarihi]", "do\u011fum_tarihi", "hasta_tc", "patient_national_id", "kimlik_numarasi",
                    "PatientSSN", "date_of_birth", "BirthDay", "net_salary", "brut_maas", "tani_kodu", "Icd10Kodu",
                    "primary_diagnosis", "anne_adi", "passport_number"):
            self.assertEqual(run(f"SELECT {col} FROM visits"), (["sql-pii"], []), col)

    def test_context_stems(self):
        for col in ("cep_tel", "ev_telefonu", "gsm2", "user_email", "email_address", "phoneNumber", "mobile_phone",
                    "address_line1", "billing_address", "ev_adresi", "hasta_adi", "ad_soyad", "isim_soyisim",
                    "patientName", "first_name", "contact_last_name"):
            self.assertEqual(run(f"SELECT {col} FROM suppliers"), ([], ["sql-pii-context"]), col)
            self.assertEqual(run(f"SELECT {col} FROM patients"), (["sql-pii"], []), col)

    def test_lookalikes_stay_clean(self):
        for col in ("id", "tc_id", "tc_status", "tanim", "panel", "dinamik", "email_verified", "phone_verified",
                    "urun_adi", "firma_adi", "hotel", "international_id", "nationality", "address_id", "dob_flag",
                    "telif", "customer_count", "birth_place"):
            self.assertEqual(run(f"SELECT {col} FROM products"), ([], []), col)

    def test_reported_offsets_and_names(self):
        sql = "SELECT p.id, [TC Kimlik No], nationalIdNumber FROM hasta p"
        found = [f for f in sqlgate.find_sql(sql) if f.rule == "sql-pii"]
        self.assertEqual([f.sample for f in found], ["tc_kimlik_no", "national_id_number"])
        self.assertEqual([sql[f.start:f.end] for f in found], ["TC Kimlik No", "nationalIdNumber"])


class PersonTableTests(unittest.TestCase):
    def test_table_name_parts(self):
        for table in ("hastalar", "tbl_patient", "v_patient", "Hasta_Kayit", "kullanicilar", "calisanlar",
                      "AspNetUsers", "tblPatients", "inpatient_visits", "dbo.[Hasta Kayit]", "#patients"):
            self.assertEqual(run(f"SELECT name FROM {table}"), (["sql-pii"], []), table)

    def test_lookalike_tables(self):
        for table in ("hastane", "hastaliklar", "remember_tokens", "buyers", "musteriler", "customers"):
            self.assertEqual(run(f"SELECT name FROM {table}"), ([], ["sql-pii-context"]), table)
            self.assertFalse(sqlgate.is_person_table(table, sqlgate.PERSON_TABLES), table)


class StarFormTests(unittest.TestCase):
    def test_temp_tables_and_qualified_stars(self):
        self.assertEqual(run("SELECT * FROM #patients"), (["sql-star"], []))
        self.assertEqual(run("SELECT [p].* FROM patients p"), (["sql-star"], []))
        self.assertEqual(run("SELECT dbo.p.* FROM patients p"), (["sql-star"], []))
        self.assertEqual(run("SELECT COUNT(*) FROM patients"), ([], []))
        self.assertEqual(run("SELECT [p].* FROM orders p"), ([], []))


class OutputListAndExportTests(unittest.TestCase):
    def test_returning_and_output_lists(self):
        self.assertEqual(run("INSERT INTO visits (pid) VALUES (1) RETURNING id, national_id"), (["sql-pii"], []))
        self.assertEqual(run("UPDATE patients SET seen = 1 RETURNING *"), (["sql-star"], []))
        self.assertEqual(run("INSERT INTO t (a) OUTPUT inserted.id, inserted.national_id VALUES (1)"), (["sql-pii"], []))
        self.assertEqual(run("DELETE FROM patients OUTPUT deleted.* WHERE id = 1"), (["sql-star"], []))
        self.assertEqual(run("INSERT INTO visits (pid) VALUES (1) RETURNING id"), ([], []))
        self.assertEqual(run("We are returning the email to the user."), ([], []))

    def test_table_exports(self):
        for cmd in ("COPY patients TO STDOUT", "COPY patients TO '/tmp/p.csv' CSV HEADER",
                    "\\copy patients to /tmp/p.csv csv", "bcp dbo.patients out p.dat -S db -T"):
            self.assertEqual(run(cmd), (["sql-star"], []), cmd)
        self.assertEqual(run("COPY visits (national_id, visit_date) TO STDOUT"), (["sql-pii"], []))
        for cmd in ("COPY orders TO STDOUT", "copy users to the clipboard", "bcp dbo.orders out o.dat"):
            self.assertEqual(run(cmd), ([], []), cmd)

    def test_looks_like_sql_knows_the_new_forms(self):
        for text in ("INSERT INTO t VALUES (1) RETURNING id", "UPDATE t SET a = 1 OUTPUT deleted.a",
                     "COPY patients TO STDOUT", "bcp dbo.patients out p.dat"):
            self.assertTrue(sqlgate.looks_like_sql(text), text)
        for text in ("returning customers", "the output is fine", "please select one", "the table users has rows"):
            self.assertFalse(sqlgate.looks_like_sql(text), text)


class WrapperAdditionTests(unittest.TestCase):
    def test_new_non_revealing_wrappers(self):
        for sql in ("SELECT COUNT(DISTINCT LOWER(email)) FROM patients",
                    "SELECT DATEDIFF(year, birth_date, GETDATE()) FROM patients",
                    "SELECT date_trunc('year', birth_date) FROM patients",
                    "SELECT TO_CHAR(birth_date, 'YYYY') FROM patients",
                    "SELECT HASHBYTES('SHA2_256', national_id), md5(email), sha256(national_id) FROM patients",
                    "SELECT AVG(salary), SUM(maas), MAX(net_salary) FROM employees"):
            self.assertEqual(run(sql), ([], []), sql)

    def test_still_revealing(self):
        for sql in ("SELECT date_trunc('day', birth_date) FROM patients", "SELECT MIN(birth_date) FROM patients",
                    "SELECT DATEDIFF(day, birth_date, GETDATE()) FROM patients", "SELECT MAX(national_id) FROM patients"):
            self.assertEqual(run(sql), (["sql-pii"], []), sql)


class OffsetTests(unittest.TestCase):
    def test_offsets_point_into_the_original_text(self):
        sql = ("-- monthly report\n/* owner: data team\n   reviewed */\nSELECT 'it''s' AS note,\n"
               "       p.national_id\nFROM patients p")
        found = list(sqlgate.find_sql(sql))
        self.assertEqual([f.rule for f in found], ["sql-pii"])
        f = found[0]
        self.assertEqual(sql[f.start:f.end], "national_id")
        self.assertEqual(sql.count("\n", 0, f.start) + 1, 5)

    def test_offsets_inside_a_quoted_query_and_after_turkish_letters(self):
        cmd = "psql -c 'SELECT do\u011fum_tarihi FROM hasta'"
        f = next(iter(sqlgate.find_sql(cmd)))
        self.assertEqual(cmd[f.start:f.end], "do\u011fum_tarihi")


class ProseTests(unittest.TestCase):
    def test_prose_mentioning_select_and_from_stays_clean(self):
        for text in (
            "The gate refuses SELECT lists that would output salary or birth dates, which is the point.\n"
            "It reads the whole file from top to bottom.",
            "- SQL gate: `SELECT` lists with sensitive columns (national IDs, birth dates, card numbers, health,\n"
            "  salary) are blocked; this works from the first release.",
            "You can select the salary of a person from the list.",
            "Please select. From there the salary is shown.",
            "SELECT, RETURNING and OUTPUT lists with sensitive columns (salary) from any table.",
            "Bu ekranda maas bilgisi ve ad ile soyad select edilir, from alan\u0131 bir tablo olan ...",
            "el.select(); const salary = row.salary; import x from 'y';",
        ):
            self.assertEqual(run(text), ([], []), text)

    def test_paragraph_break_ends_a_list(self):
        self.assertEqual(run("select one option\n\nsalary and national_id are listed from the table"), ([], []))
        self.assertEqual(run("## Select lists\n\nColumns such as salary are blocked from now on."), ([], []))

    def test_blank_lines_inside_a_select_list(self):
        for sql in ("SELECT id,\n\n       national_id, tckn, salary\nFROM patients",
                    "SELECT id\n\n     , national_id\nFROM visits",
                    "SELECT\n\n    national_id\nFROM visits",
                    "SELECT DISTINCT\n\n    national_id\nFROM visits",
                    "SELECT\n    p.id,\n\n    -- identity\n    p.national_id\n\nFROM patients p",
                    "SELECT id, /* a\n\n b */ national_id FROM visits",
                    "SELECT 'a\n\nb' AS note, national_id FROM visits"):
            self.assertEqual(run(sql)[0], ["sql-pii"], sql)

    def test_quote_right_after_select(self):
        for sql in ('SELECT"national_id" FROM patients', "SELECT`national_id` FROM patients",
                    "SELECT[national_id] FROM patients", "SELECT'x' AS a, national_id FROM visits"):
            self.assertEqual(run(sql)[0], ["sql-pii"], sql)
        for text in ('The "SELECT" salary list comes from the docs.', "The `SELECT` salary list comes from the docs."):
            self.assertEqual(run(text), ([], []), text)

    def test_quoted_aliases_do_not_read_as_prose(self):
        for sql in ('SELECT national_id AS "date of birth", salary AS "paid to employee" FROM patients',
                    "SELECT national_id AS `date of birth`, salary AS `paid to employee` FROM patients",
                    "SELECT national_id AS [date of birth], salary AS [paid to employee] FROM patients",
                    "SELECT national_id AS 'date of birth', salary AS 'paid to the employee' FROM patients"):
            self.assertEqual(run(sql)[0], ["sql-pii"], sql)
        for text in ('print("Please select the salary of an employee from the menu")',
                     'msg = "You can select the salary of a person from the list"'):
            self.assertEqual(run(text), ([], []), text)

    def test_many_selects_before_one_far_from_are_linear(self):
        # Every SELECT here reads as prose up to the same FROM; each used to rescan the whole window
        # (15 blocks took ~25 s). The prose verdict now costs a binary search.
        t0 = time.perf_counter()
        list(sqlgate.find_sql((("select " * 2500) + "the a from t\n\n") * 15))         # 263 KB
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_select_runs_are_linear(self):
        t0 = time.perf_counter()
        for text in ("select " * 20000, "select " * 20000 + "from t", "select the " * 20000 + "from t",
                     "select\n\n" * 20000 + "from t"):
            list(sqlgate.find_sql(text))
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_paragraph_breaks_and_quoted_names_are_linear(self):
        t0 = time.perf_counter()
        for text in ("select a,\n\n" * 5000 + "from t", "select a, " + " " * 300000 + "\n\nfrom t",
                     "select a\n" + "\n" * 300000 + "from t", 'select a as "x of y", ' * 5000 + "from t"):
            list(sqlgate.find_sql(text))
        self.assertLess(time.perf_counter() - t0, 1.0)

    def test_real_queries_still_block(self):
        for sql in ("SELECT national_id FROM patients",
                    "SELECT TOP 10 p.tckn, p.ad AS the_name FROM hasta p",
                    "SELECT a.name, a.email FROM users a",
                    "WITH recent AS (\n  SELECT pid FROM visits\n)\nSELECT p.national_id\nFROM patients p\n"
                    "JOIN recent r ON r.pid = p.id",
                    "SELECT\n    p.id,\n    p.birth_date\nFROM\n    patients p\nWHERE p.id > 10",
                    "SELECT id\n  , national_id\nFROM patients"):
            self.assertEqual(run(sql)[0], ["sql-pii"], sql)


if __name__ == "__main__":
    unittest.main()
