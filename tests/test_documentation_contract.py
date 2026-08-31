import json
import os
import re
import subprocess
import unittest
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
VERSION = (ROOT / ".agents" / "skills" / "contextsec" / "VERSION").read_text(
    encoding="utf-8"
).strip()
ONBOARDING = (
    ROOT / "README.md",
    ROOT / "docs" / "i18n" / "README.zh-TW.md",
    ROOT / "docs" / "i18n" / "README.zh-CN.md",
    ROOT / "docs" / "i18n" / "README.ja.md",
)


class DocumentationContractTests(unittest.TestCase):
    def test_onboarding_keeps_languages_version_and_platforms_in_sync(self):
        language_links = (
            "README.md",
            "README.zh-TW.md",
            "README.zh-CN.md",
            "README.ja.md",
        )
        for document in ONBOARDING:
            text = document.read_text(encoding="utf-8")
            with self.subTest(document=document.name):
                self.assertIn("contextsec-hero.svg", text)
                self.assertIn("v" + VERSION, text)
                self.assertNotRegex(text, r"\\\s*\n")
                for language_link in language_links:
                    self.assertIn(language_link, text)
                self.assertIn("### Windows", text)
                self.assertIn("python --version", text)
                self.assertIn(
                    "python .agents/skills/contextsec/scripts/contextsec.py doctor",
                    text,
                )
                self.assertIn("### macOS", text)
                self.assertIn("### Linux", text)
                self.assertGreaterEqual(text.count("python3 --version"), 2)
                self.assertGreaterEqual(
                    text.count(
                        "python3 .agents/skills/contextsec/scripts/contextsec.py doctor"
                    ),
                    2,
                )

    def test_onboarding_local_links_resolve(self):
        markdown_link = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
        html_source = re.compile(r"\b(?:src|href)=\"([^\"]+)\"")
        for document in ONBOARDING + (ROOT / "docs" / "README.md",):
            text = document.read_text(encoding="utf-8")
            targets = markdown_link.findall(text) + html_source.findall(text)
            for target in targets:
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                clean = unquote(target.split("#", 1)[0])
                if not clean:
                    continue
                resolved = (document.parent / clean).resolve()
                with self.subTest(document=document.name, target=target):
                    self.assertTrue(resolved.exists(), str(resolved))

    def test_hero_is_accessible_svg(self):
        hero = ROOT / "docs" / "assets" / "contextsec-hero.svg"
        root = ElementTree.parse(hero).getroot()
        namespace = {"svg": "http://www.w3.org/2000/svg"}
        self.assertEqual("img", root.attrib.get("role"))
        self.assertIsNotNone(root.find("svg:title", namespace))
        self.assertIsNotNone(root.find("svg:desc", namespace))
        self.assertIn(VERSION, "".join(root.itertext()))

    def test_documented_first_run_result(self):
        cli = (
            ROOT
            / ".agents"
            / "skills"
            / "contextsec"
            / "scripts"
            / "contextsec.py"
        )
        fixture = ROOT / "examples" / "composite-saas"
        documented_interpreter = "python" if os.name == "nt" else "python3"

        doctor = subprocess.run(
            [documented_interpreter, str(cli), "doctor"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            encoding="utf-8",
        )
        self.assertTrue(json.loads(doctor.stdout)["python_supported"])

        profile = subprocess.run(
            [
                documented_interpreter,
                str(cli),
                "profile",
                "--repo",
                str(fixture),
                "--format",
                "markdown",
            ],
            cwd=ROOT,
            capture_output=True,
            check=True,
            encoding="utf-8",
        )
        self.assertIn("`payments` | required", profile.stdout)
        self.assertIn("`ai-rag-agent` | required", profile.stdout)

        checks = subprocess.run(
            [documented_interpreter, str(cli), "check", "--repo", str(fixture)],
            cwd=ROOT,
            capture_output=True,
            check=True,
            encoding="utf-8",
        )
        finding_summary = json.loads(checks.stdout)["finding_summary"]
        self.assertEqual(5, finding_summary["failed_findings"])
        self.assertEqual(1, finding_summary["unknown_findings"])
        self.assertEqual(0, finding_summary["verified_findings"])

        gate = subprocess.run(
            [documented_interpreter, str(cli), "gate", "--repo", str(fixture)],
            cwd=ROOT,
            capture_output=True,
            check=False,
            encoding="utf-8",
        )
        self.assertEqual(1, gate.returncode)
        self.assertEqual("BLOCK", json.loads(gate.stdout)["gate"]["status"])


if __name__ == "__main__":
    unittest.main()
