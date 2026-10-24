import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from pii_gate import cli, config

import _synthetic as syn


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self._saved = {k: os.environ.pop(k, None) for k in (config.ENV_VAR, *config.PROJECT_ROOT_VARS)}

    def tearDown(self):
        os.chdir(self.cwd)
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
        self.tmp.cleanup()

    def test_check(self):
        code, out, _ = run(["check", f"customer {syn.TCKN_A}"])
        self.assertEqual(code, 1)
        self.assertIn("BLOCK  tckn", out)
        self.assertNotIn(syn.TCKN_A, out)
        self.assertEqual(run(["check", "hello world"])[:2], (0, "clean\n"))
        self.assertEqual(run(["check", "--command", "git push"])[0], 1)
        self.assertEqual(run(["check", "git push"])[0], 0)  # exfil rules only apply to commands
        code, out, _ = run(["check", "SELECT phone FROM suppliers"])
        self.assertEqual(code, 0)
        self.assertIn("warn   sql-pii-context", out)

    def test_scan_files_and_allow_paths(self):
        Path("src").mkdir()
        Path("src", "a.py").write_text(f"X = '{syn.IBAN_TR}'\n", encoding="utf-8")
        Path("src", "b.bin").write_bytes(b"\x00\x01" + syn.TCKN_A.encode())
        Path("tests").mkdir()
        Path("tests", "fx.json").write_text(json.dumps({"id": syn.TCKN_B}), encoding="utf-8")
        Path("pkg.egg-info").mkdir()
        Path("pkg.egg-info", "PKG-INFO").write_text(syn.TCKN_A, encoding="utf-8")
        code, out, _ = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertIn("BLOCK iban", out)
        self.assertIn("BLOCK tckn", out)
        self.assertNotIn("b.bin", out)
        self.assertNotIn("egg-info", out)
        Path(".pii-gate.json").write_text(json.dumps({"allow_paths": ["tests/*"]}), encoding="utf-8")
        code, out, _ = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertNotIn("tckn", out)
        Path("src", "a.py").write_text("X = 1\n", encoding="utf-8")
        self.assertEqual(run(["scan", "."])[0], 0)

    def test_scan_missing_root_is_an_error(self):
        code, out, err = run(["scan", "no-such-dir"])
        self.assertEqual(code, 2)
        self.assertIn("no-such-dir", err)
        self.assertNotIn("clean", out)

    def test_scan_reports_skipped_files(self):
        Path("big.txt").write_bytes(f"{syn.TCKN_A}\n{'x' * 2000}\n".encode())
        Path("blob.bin").write_bytes(b"\x00\x01" + syn.TCKN_A.encode())
        code, out, err = run(["scan", "--max-bytes", "1000", "."])
        self.assertEqual(code, 0)
        self.assertIn("skipped: 2 file(s) (too large or binary):", err)
        self.assertIn("big.txt", err)
        self.assertIn("blob.bin", err)
        self.assertIn("clean: 0 blocking finding(s), 2 file(s) skipped", out)
        Path("a.py").write_text(f"X = '{syn.IBAN_TR}'\n", encoding="utf-8")
        code, out, err = run(["scan", "--max-bytes", "1000", "."])
        self.assertEqual(code, 1)
        self.assertIn("skipped: 2 file(s)", err)
        code, out, err = run(["scan", "."])  # default limit is 5 MB: big.txt is scanned now
        self.assertEqual(code, 1)
        self.assertIn("big.txt:1: BLOCK tckn", out)
        self.assertIn("skipped: 1 file(s)", err)

    def test_scan_explicit_files(self):  # what pre-commit passes (pass_filenames: true)
        Path("a.py").write_text(f"X = '{syn.IBAN_TR}'\n", encoding="utf-8")
        Path("b.py").write_text("Y = 2\n", encoding="utf-8")
        Path("tests").mkdir()
        Path("tests", "fx.py").write_text(f"Z = '{syn.TCKN_A}'\n", encoding="utf-8")
        Path(".pii-gate.json").write_text(json.dumps({"allow_paths": ["tests/*"]}), encoding="utf-8")
        code, out, _ = run(["scan", "a.py", "b.py", os.path.join("tests", "fx.py")])
        self.assertEqual(code, 1)
        self.assertIn("a.py:1: BLOCK iban", out)
        self.assertNotIn("tckn", out)
        self.assertEqual(run(["scan", "b.py", os.path.join("tests", "fx.py")])[0], 0)

    def test_scan_utf16_files(self):
        Path("le.txt").write_bytes(f"id {syn.TCKN_A}\r\n".encode("utf-16"))  # BOM + native order
        Path("be.txt").write_bytes(b"\xfe\xff" + f"line\n{syn.TCKN_B}\n".encode("utf-16-be"))
        code, out, err = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertIn("le.txt:1: BLOCK tckn", out)
        self.assertIn("be.txt:2: BLOCK tckn", out)
        self.assertEqual(err, "")

    def test_scan_whole_file_multiline_sql_and_line_numbers(self):
        Path("q.sql").write_bytes(b"USE clinic;\nSELECT\n national_id\nFROM patients\n")
        Path("w.py").write_bytes(f"a = 1\r\nb = 2\r\nc = '{syn.IBAN_TR}'\r\n".encode())
        code, out, _ = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertIn('q.sql:3: BLOCK sql-pii (sensitive column in SELECT list, "national_id")', out)
        self.assertIn("w.py:3: BLOCK iban", out)

    def test_parse_staged_diff(self):
        diff = "\n".join([
            "diff --git a/x.py b/x.py",
            "index 1111111..2222222 100644",
            "--- a/x.py",
            "+++ b/x.py",
            "@@ -3 +3,2 @@",
            "--- a removed line that starts with two dashes",
            "+++y = 1",
            "+z = 2",
            "@@ -10,0 +12 @@",
            "+w = 3",
            "diff --git a/my file.py b/my file.py",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/my file.py\t",
            "@@ -0,0 +1 @@",
            "+hello",
            "diff --git a/gone.py b/gone.py",
            "deleted file mode 100644",
            "--- a/gone.py",
            "+++ /dev/null",
            "@@ -1 +0,0 @@",
            "-bye",
            'diff --git "a/t\\303\\244b\\"q.py" "b/t\\303\\244b\\"q.py"',
            "--- /dev/null",
            '+++ "b/t\\303\\244b\\"q.py"',
            "@@ -0,0 +1 @@",
            "+v = 4",
            "",
        ])
        self.assertEqual(cli.parse_staged_diff(diff), [
            ("x.py", [(3, "++y = 1"), (4, "z = 2"), (12, "w = 3")]),
            ("my file.py", [(1, "hello")]),
            ('täb"q.py', [(1, "v = 4")]),
        ])

    @unittest.skipIf(shutil.which("git") is None, "git not available")
    def test_scan_staged_real_repo(self):
        def git(*argv):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                            "-c", "commit.gpgsign=false", *argv], check=True, capture_output=True)

        git("init", "-q")
        git("config", "diff.mnemonicPrefix", "true")  # would turn b/ into w/ or i/
        git("config", "core.quotePath", "true")       # would quote the non-ASCII path
        git("config", "diff.renames", "true")
        Path(".pii-gate.json").write_text(json.dumps({"allow_paths": ["tests/*"]}), encoding="utf-8")
        Path("tests").mkdir()
        Path("src").mkdir()
        Path("tests", "fx.py").write_bytes(f"ID = '{syn.TCKN_A}'\n".encode())
        git("add", "-A")
        git("commit", "-q", "--no-verify", "-m", "fixture")
        self.assertIn("clean", run(["scan", "--staged"])[1])

        git("mv", "tests/fx.py", "src/fx.py")                           # rename out of an allowed dir
        Path("my file.py").write_bytes(f"a = 1\n++x = '{syn.IBAN_TR}'\n".encode())  # space + "++"
        Path("şehir.sql").write_bytes(b"SELECT\n national_id\nFROM patients\n")  # non-ASCII name
        Path("tests", "new.py").write_bytes(f"B = '{syn.TCKN_B}'\n".encode())  # allowed
        git("add", "-A")
        code, out, _ = run(["scan", "--staged"])
        self.assertEqual(code, 1, out)
        self.assertIn("src/fx.py:1: BLOCK tckn", out)
        self.assertIn("my file.py:2: BLOCK iban", out)
        self.assertIn("şehir.sql:2: BLOCK sql-pii", out)
        self.assertNotIn("new.py", out)
        self.assertNotIn("\t", out)
        self.assertIn("BLOCKED: 3 blocking finding(s)", out)

    def test_unencodable_console_does_not_crash(self):
        Path("日本.py").write_text(f"X = '{syn.IBAN_TR}'\n", encoding="utf-8")
        buf = io.BytesIO()
        console = io.TextIOWrapper(buf, encoding="cp1254", errors="strict")
        with contextlib.redirect_stdout(console), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["scan", "."])
        console.flush()
        self.assertEqual(code, 1)
        self.assertIn(b"\\u65e5\\u672c.py:1: BLOCK iban", buf.getvalue())

    def test_installer_errors_exit_2(self):
        Path(".claude").mkdir()
        Path(".claude", "settings.local.json").write_text("{not json", encoding="utf-8")
        code, _, err = run(["install", "claude", "--project"])
        self.assertEqual(code, 2)
        self.assertTrue(err.startswith("pii-gate: "), err)
        self.assertIn("not valid JSON", err)
        self.assertNotIn("Traceback", err)

    def test_status_and_version(self):
        code, out, _ = run(["status"])
        self.assertEqual(code, 0)
        self.assertIn("config: defaults", out)
        self.assertIn("codex", out)
        self.assertIn(f"project root: {os.getcwd()}", out)
        self.assertIn(f"[ ] {Path(os.getcwd()) / '.pii-gate.json'}", out)
        Path(".pii-gate.json").write_text("{}", encoding="utf-8")
        self.assertIn(f"[x] {Path(os.getcwd()) / '.pii-gate.json'}", run(["status"])[1])
        with self.assertRaises(SystemExit) as ctx:
            run(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_config_error_exit_code(self):
        Path(".pii-gate.json").write_text('{"rules": {"tckn": "sometimes"}}', encoding="utf-8")
        code, _, err = run(["check", "x"])
        self.assertEqual(code, 2)
        self.assertIn("config error", err)


if __name__ == "__main__":
    unittest.main()
