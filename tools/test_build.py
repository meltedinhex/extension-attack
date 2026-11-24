import copy
import json
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import build


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.hrefs.extend(value for key, value in attrs if key == "href")


class BuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tactics = build.load_tactics()
        cls.techniques = build.load_techniques()

    def test_matrix_does_not_mutate_source(self):
        before = copy.deepcopy(self.techniques)
        matrix = build.build_matrix_json(self.techniques, self.tactics)
        self.assertEqual(before, self.techniques)
        self.assertNotIn("coverage", matrix["counts"])
        by_id = {t["id"]: t for t in matrix["techniques"]}
        for t in by_id.values():
            for related in t.get("related", []):
                self.assertIn(t["id"], by_id[related]["related"])

    def test_invalid_references_and_missing_examples_fail(self):
        techniques = copy.deepcopy(self.techniques)
        active = next(t for t in techniques if t["status"] == "active")
        active["real_world_examples"] = []
        active["related"] = ["EXT-COLL-999"]
        errors = build.validate(techniques, self.tactics)
        self.assertTrue(any("related" in e for e in errors))
        self.assertTrue(any("real_world_examples" in e for e in errors))

    def test_page_escaping_and_field_parity(self):
        technique = copy.deepcopy(self.techniques[0])
        technique["scope_note"] = 'Scope <test> "quoted"'
        technique["manifest_fingerprint"] = ["fingerprint-marker"]
        technique["real_world_examples"] = [{
            "title": "Example", "url": 'https://example.org/" onmouseover="bad',
        }]
        page = build.build_technique_page(technique)
        self.assertIn("Scope &lt;test&gt; &quot;quoted&quot;", page)
        self.assertIn("fingerprint-marker", page)
        self.assertNotIn('" onmouseover="bad', page)
        self.assertEqual("#", build._safe_url("javascript:alert(1)"))

    def test_generated_output_links(self):
        root = build.BUILD / "heatmap"
        matrix = json.loads((root / "matrix.json").read_text(encoding="utf-8"))
        expected = {t["id"] + ".html" for t in matrix["techniques"]}
        self.assertEqual(expected, {p.name for p in (root / "techniques").glob("*.html")})
        for page in root.rglob("*.html"):
            parser = Links()
            parser.feed(page.read_text(encoding="utf-8"))
            for href in parser.hrefs:
                parsed = urlsplit(href)
                if not parsed.scheme and parsed.path:
                    target = page.parent / unquote(parsed.path)
                    self.assertTrue(target.is_file(), f"{page.name}: missing {href}")
        for name in ("matrix.json", "navigator-layer.json", "extension-attack-stix.json"):
            self.assertEqual((build.BUILD / name).read_bytes(), (root / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
