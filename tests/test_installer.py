import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from pii_gate import installer

import _synthetic as syn

SRC = str(Path(__file__).resolve().parents[1] / "src")


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        self.proj = str(Path(self.tmp.name) / "proj")
        Path(self.proj).mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def test_codex_user_install_is_idempotent_and_fails_closed_on_launch_errors(self):
        path = installer.install("codex", home=self.home, python="/usr/bin/python3")
        self.assertEqual(path, Path(self.home) / ".codex" / "hooks.json")
        data = self.read(path)
        pre = data["hooks"]["PreToolUse"]
        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0]["matcher"], ".*")
        command = pre[0]["hooks"][0]["command"]
        self.assertTrue(command.startswith("/usr/bin/python3 "), command)
        self.assertIn("pii_gate", command)
        self.assertIn("exit 2", command)                      # a missing interpreter still blocks
        self.assertIn("exit /b 2", pre[0]["hooks"][0]["commandWindows"])
        self.assertEqual(pre[0]["hooks"][0]["timeout"], installer.TIMEOUT)
        self.assertEqual(len(data["hooks"]["UserPromptSubmit"]), 1)
        installer.install("codex", home=self.home, python="/usr/bin/python3")
        self.assertEqual(len(self.read(path)["hooks"]["PreToolUse"]), 1)

    def test_claude_uses_exec_form_with_on_failure_block(self):
        path = installer.install("claude", home=self.home, python="py")
        handler = self.read(path)["hooks"]["PreToolUse"][0]["hooks"][0]
        self.assertEqual(handler["command"], "py")
        self.assertEqual(handler["args"][-3:], ["-m", "pii_gate", "hook"] if sys.version_info >= (3, 11)
                         else ["-c", installer._SAFE_MODULE_RUN])
        self.assertEqual(handler["onFailure"], "block")
        self.assertEqual(handler["timeout"], installer.TIMEOUT)
        self.assertNotIn("matcher", self.read(path)["hooks"]["PreToolUse"][0])

    def test_default_program_keeps_cwd_off_sys_path(self):
        program, args = installer.hook_program()
        if args == ["hook"]:
            self.assertTrue(Path(program).is_file() and "pii-gate" in Path(program).name)
        else:
            self.assertTrue(args[0] in ("-P", "-c"), args)

    def test_claude_project_install_targets_settings_local_and_keeps_other_settings(self):
        path = Path(self.proj) / ".claude" / "settings.local.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"permissions": {"allow": ["Bash(ls *)"]},
                                    "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                                        {"type": "command", "command": "echo other"}]}]}}), encoding="utf-8")
        self.assertEqual(installer.install("claude", project=True, cwd=self.proj, python="py"), path)
        data = self.read(path)
        self.assertEqual(data["permissions"], {"allow": ["Bash(ls *)"]})
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 2)
        self.assertEqual(data["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "echo other")
        self.assertEqual(data["hooks"]["PreToolUse"][1]["hooks"][0]["command"], "py")
        self.assertFalse((Path(self.proj) / ".claude" / "settings.json").exists())

    def test_reinstall_replaces_stale_command(self):
        path = installer.install("claude", home=self.home, python="/old/python")
        installer.install("claude", home=self.home, python="/new/python")
        pre = self.read(path)["hooks"]["PreToolUse"]
        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0]["hooks"][0]["command"], "/new/python")

    def test_gemini_install(self):
        path = installer.install("gemini", home=self.home, python="py")
        self.assertEqual(path, Path(self.home) / ".gemini" / "settings.json")
        data = self.read(path)
        self.assertEqual(data["hooks"]["BeforeTool"][0]["matcher"], "*")
        handler = data["hooks"]["BeforeTool"][0]["hooks"][0]
        self.assertEqual(handler["name"], "pii-gate")
        self.assertEqual(handler["timeout"], installer.TIMEOUT * 1000)      # Gemini counts milliseconds
        self.assertIn("BeforeAgent", data["hooks"])

    def test_uninstall_removes_only_ours(self):
        path = Path(self.home) / ".claude" / "settings.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "echo other"}]}]}}), encoding="utf-8")
        installer.install("claude", home=self.home, python="py")
        installer.uninstall("claude", home=self.home)
        data = self.read(path)
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 1)
        self.assertNotIn("UserPromptSubmit", data["hooks"])
        for agent in ("codex", "gemini"):
            installer.install(agent, home=self.home, python="py")
            installer.uninstall(agent, home=self.home)
            self.assertEqual(self.read(installer.target(agent, False, home=self.home)), {})

    def test_non_ascii_settings_survive(self):
        path = Path(self.home) / ".claude" / "settings.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"note": "Türkçe ğüşiöç"}, ensure_ascii=False), encoding="utf-8")
        installer.install("claude", home=self.home, python="py")
        self.assertIn("Türkçe ğüşiöç", path.read_text(encoding="utf-8"))

    def test_malformed_settings_are_reported_not_overwritten(self):
        path = Path(self.home) / ".claude" / "settings.json"
        path.parent.mkdir()
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            installer.install("claude", home=self.home, python="py")
        self.assertEqual(path.read_text(encoding="utf-8"), "{not json")

    def test_uninstall_missing_file_is_noop(self):
        installer.uninstall("codex", home=self.home)
        self.assertFalse((Path(self.home) / ".codex" / "hooks.json").exists())

    def test_status_reports_missing_program(self):
        installer.install("codex", home=self.home, python="py")
        lines = installer.status(cwd=self.proj, home=self.home)
        self.assertEqual(len(lines), 6)
        self.assertIn("installed (PreToolUse, UserPromptSubmit)", lines[0])
        self.assertTrue(all("missing" in line for line in lines[1:]))
        installer.install("claude", home=self.home, python="/nonexistent/python")
        lines = installer.status(cwd=self.proj, home=self.home)
        self.assertIn("hook program is missing", lines[2])

    def test_bad_agent(self):
        with self.assertRaises(ValueError):
            installer.install("cursor", home=self.home)


class ShadowingTests(unittest.TestCase):
    """The installed command must not import modules from the agent's working directory."""

    def test_hook_program_ignores_modules_in_cwd(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "json.py").write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
            Path(tmp, "pii_gate").mkdir()
            Path(tmp, "pii_gate", "__init__.py").write_text("", encoding="utf-8")
            Path(tmp, "pii_gate", "__main__.py").write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
            cfg = Path(tmp, "cfg.json")
            cfg.write_text(json.dumps({"log": False}), encoding="utf-8")
            env = {**os.environ, "PYTHONPATH": SRC, "PII_GATE_CONFIG": str(cfg)}
            payload = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                  "tool_input": {"command": f"echo {syn.TCKN_A}"}, "cwd": tmp})
            program, args = installer.hook_program(sys.executable)
            proc = subprocess.run([program, *args], input=payload, capture_output=True, text=True, env=env, cwd=tmp)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("tckn", proc.stderr)


if __name__ == "__main__":
    unittest.main()
