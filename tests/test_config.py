import json
import os
import tempfile
import unittest
from pathlib import Path

from pii_gate import config


class ParseTests(unittest.TestCase):
    def test_defaults(self):
        cfg = config.Config()
        self.assertEqual(cfg.level("tckn"), "block")
        self.assertEqual(cfg.level("read"), "block")
        self.assertEqual(cfg.level("email"), "warn")
        self.assertEqual(cfg.level("unknown-future-rule"), "block")
        self.assertFalse(cfg.fail_open)

    def test_overrides(self):
        cfg = config.parse({"rules": {"email": "block", "git-push": "off"}, "allow_values": ["x"],
                            "allow_paths": ["tests/*"], "email_allow_domains": ["corp.example"],
                            "scan_prompts": False, "fail_open": True, "log": False})
        self.assertEqual(cfg.level("email"), "block")
        self.assertEqual(cfg.level("git-push"), "off")
        self.assertEqual(cfg.allow_values, {"x"})
        self.assertFalse(cfg.scan_prompts)
        self.assertTrue(cfg.fail_open)

    def test_errors(self):
        for bad in ({"rules": {"nope": "block"}}, {"rules": {"tckn": "maybe"}}, {"allow_values": "not-a-list"},
                    {"fail_open": "yes"}, [], {"allow_value": ["typo"]}, {"sql": {"extra_pii_column": ["typo"]}}):
            with self.assertRaises(config.ConfigError, msg=bad):
                config.parse(bad)

    def test_project_file_may_only_tighten(self):
        cfg = config.apply(config.Config(), {"rules": {"email": "block"}, "allow_paths": ["tests/*"],
                                             "sql": {"extra_pii_columns": ["protocol_no"]}}, "p", trusted=False)
        self.assertEqual(cfg.level("email"), "block")
        self.assertIn("protocol_no", cfg.sql_extra_columns)
        for loosening in ({"rules": {"tckn": "warn"}}, {"rules": {"git-push": "off"}}, {"fail_open": True},
                          {"scan_prompts": False}, {"log": False}, {"allow_paths": ["/*"]},
                          {"allow_paths": ["C:/*"]}, {"allow_paths": ["../*"]}, {"allow_paths": ["~/*"]}):
            with self.assertRaises(config.ConfigError, msg=loosening):
                config.apply(config.Config(), loosening, "p", trusted=False)


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.proj = Path(self.tmp.name) / "proj"
        self.home.mkdir()
        self.proj.mkdir()
        (self.proj / ".git").mkdir()
        self._saved = {k: os.environ.pop(k, None) for k in (config.ENV_VAR, *config.PROJECT_ROOT_VARS)}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
        self.tmp.cleanup()

    def load(self, cwd=None):
        return config.load(cwd=str(cwd or self.proj), home=str(self.home))

    def test_home_then_project_on_top_then_env_replaces_all(self):
        (self.home / ".pii-gate.json").write_text(json.dumps({"rules": {"email": "block"}}), encoding="utf-8")
        self.assertEqual(self.load().level("email"), "block")
        (self.proj / ".pii-gate.json").write_text(json.dumps({"rules": {"phone": "block"},
                                                              "allow_paths": ["tests/*"]}), encoding="utf-8")
        cfg = self.load()
        self.assertEqual((cfg.level("email"), cfg.level("phone")), ("block", "block"))
        self.assertEqual(cfg.allow_paths, ["tests/*"])
        self.assertIn("+", cfg.source)
        env_file = Path(self.tmp.name) / "env.json"
        env_file.write_text(json.dumps({"rules": {"email": "warn"}}), encoding="utf-8")
        os.environ[config.ENV_VAR] = str(env_file)
        cfg = self.load()
        self.assertEqual(cfg.level("email"), "warn")
        self.assertEqual(cfg.allow_paths, [])

    def test_untrusted_project_file_cannot_loosen_unless_home_says_so(self):
        (self.proj / ".pii-gate.json").write_text(json.dumps({"rules": {"email": "off"}}), encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            self.load()
        (self.home / ".pii-gate.json").write_text(json.dumps({"trust_project_config": True}), encoding="utf-8")
        self.assertEqual(self.load().level("email"), "off")

    def test_project_config_is_found_from_a_subdirectory_and_not_from_a_clone(self):
        (self.proj / ".pii-gate.json").write_text(json.dumps({"rules": {"email": "block"}}), encoding="utf-8")
        sub = self.proj / "src" / "deep"
        sub.mkdir(parents=True)
        self.assertEqual(self.load(sub).level("email"), "block")
        clone = self.proj / "vendor" / "clone"
        clone.mkdir(parents=True)
        (clone / ".git").mkdir()
        (clone / ".pii-gate.json").write_text(json.dumps({"rules": {"email": "off"}}), encoding="utf-8")
        os.environ["CLAUDE_PROJECT_DIR"] = str(self.proj)      # the agent cd'ed into the clone
        self.assertEqual(self.load(clone).level("email"), "block")

    def test_env_pointing_to_missing_file_is_an_error(self):
        os.environ[config.ENV_VAR] = str(Path(self.tmp.name) / "nope.json")
        with self.assertRaises(config.ConfigError):
            self.load()

    def test_no_file_means_defaults(self):
        cfg = self.load()
        self.assertEqual(cfg.source, "defaults")

    def test_broken_json_is_a_config_error(self):
        (self.proj / ".pii-gate.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            self.load()


if __name__ == "__main__":
    unittest.main()
