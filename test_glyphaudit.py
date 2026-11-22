#!/usr/bin/env python3
"""Tests for glyphaudit.py (stdlib unittest)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "glyphaudit.py")


def run(args, cwd=None):
    return subprocess.run(
        [sys.executable, TOOL] + args,
        capture_output=True, text=True, cwd=cwd)


def write(path, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as fh:
        fh.write(data)


class GlyphAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def scan_json(self, *extra):
        proc = run(["scan", self.root, "--json"] + list(extra))
        return proc, json.loads(proc.stdout)

    def rules(self, report):
        return [(f["rule"], f["line"]) for f in report["findings"]]

    def test_clean_file_no_findings(self):
        write(os.path.join(self.root, "ok.txt"), "hello\nworld\n")
        proc, report = self.scan_json()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["counts"]["files_scanned"], 1)

    def test_invalid_utf8_offset_and_line(self):
        write(os.path.join(self.root, "bad.txt"), b"fine\nbad \xff here\n")
        proc, report = self.scan_json()
        self.assertEqual(proc.returncode, 1)
        hits = [f for f in report["findings"] if f["rule"] == "invalid-utf8"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 2)
        self.assertEqual(hits[0]["detail"], "offset 9")
        self.assertEqual(hits[0]["severity"], "high")

    def test_utf16_bom_ends_analysis(self):
        write(os.path.join(self.root, "u.txt"), b"\xff\xfeh\x00i\x00")
        proc, report = self.scan_json()
        hits = report["findings"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["rule"], "utf16-bom")
        self.assertEqual(hits[0]["detail"], "utf-16-le")

    def test_utf8_bom_then_content_still_audited(self):
        write(os.path.join(self.root, "b.txt"), b"\xef\xbb\xbfhi \n")
        proc, report = self.scan_json()
        self.assertIn(("bom-present", 1), self.rules(report))
        self.assertIn(("trailing-whitespace", 1), self.rules(report))

    def test_binary_skipped(self):
        write(os.path.join(self.root, "bin.dat"), b"a\x00b\xff")
        proc, report = self.scan_json()
        self.assertEqual(report["counts"]["files_skipped_binary"], 1)
        self.assertEqual(report["counts"]["files_scanned"], 0)
        self.assertEqual(report["findings"], [])

    def test_mixed_line_endings_and_cr_only(self):
        write(os.path.join(self.root, "m.txt"), b"one\r\ntwo\nthree\rfour\n")
        proc, report = self.scan_json()
        self.assertIn(("mixed-line-endings", 2), self.rules(report))
        self.assertIn(("cr-only", 3), self.rules(report))

    def test_crlf_only_is_not_mixed(self):
        write(os.path.join(self.root, "w.txt"), b"one\r\ntwo\r\n")
        proc, report = self.scan_json()
        self.assertEqual(report["findings"], [])

    def test_no_final_newline(self):
        write(os.path.join(self.root, "n.txt"), "abc\ndef")
        proc, report = self.scan_json()
        self.assertIn(("no-final-newline", 2), self.rules(report))

    def test_trailing_whitespace_and_long_line(self):
        write(os.path.join(self.root, "t.txt"), "short \n" + "x" * 25 + "\n")
        proc, report = self.scan_json("--max-line", "10")
        self.assertIn(("trailing-whitespace", 1), self.rules(report))
        hits = [f for f in report["findings"] if f["rule"] == "long-line"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["detail"], "25 chars")

    def test_control_char(self):
        write(os.path.join(self.root, "c.txt"), b"a\x07b\nok\ttab\n")
        proc, report = self.scan_json()
        hits = [f for f in report["findings"] if f["rule"] == "control-char"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["line"], 1)
        self.assertEqual(hits[0]["detail"], "U+0007")

    def test_mixed_indent(self):
        write(os.path.join(self.root, "i.py"), "\tone\n    two\n\tthree\n")
        proc, report = self.scan_json()
        self.assertIn(("mixed-indent", 2), self.rules(report))

    def test_single_indent_kind_is_clean(self):
        write(os.path.join(self.root, "i.py"), "    one\n    two\n")
        proc, report = self.scan_json()
        self.assertEqual(report["findings"], [])

    def test_empty_file_clean(self):
        write(os.path.join(self.root, "e.txt"), b"")
        proc, report = self.scan_json()
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["counts"]["files_scanned"], 1)

    def test_symlink_never_followed(self):
        target = os.path.join(self.root, "real.txt")
        write(target, b"bad \xff\n")
        os.symlink(target, os.path.join(self.root, "link.txt"))
        proc, report = self.scan_json()
        self.assertEqual(report["counts"]["links_skipped"], 1)
        self.assertEqual(report["counts"]["files_scanned"], 1)

    def test_extensions_filter(self):
        write(os.path.join(self.root, "a.txt"), b"bad \xff\n")
        write(os.path.join(self.root, "b.md"), b"bad \xff\n")
        proc, report = self.scan_json("--extensions", ".md")
        self.assertEqual(report["counts"]["files_scanned"], 1)
        self.assertTrue(report["findings"][0]["path"].endswith("b.md"))

    def test_min_severity_filters_output_and_exit(self):
        write(os.path.join(self.root, "t.txt"), "trailing \n")
        proc = run(["scan", self.root, "--min-severity", "high",
                    "--fail-on", "low"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("0 findings", proc.stdout)

    def test_fail_on_never(self):
        write(os.path.join(self.root, "bad.txt"), b"\xff\n")
        proc = run(["scan", self.root, "--fail-on", "never"])
        self.assertEqual(proc.returncode, 0)

    def test_missing_root_exit_2_no_traceback(self):
        proc = run(["scan", os.path.join(self.root, "nope")])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_bad_max_line_exit_2(self):
        proc = run(["scan", self.root, "--max-line", "0"])
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("Traceback", proc.stderr)

    def test_file_as_root(self):
        path = os.path.join(self.root, "one.txt")
        write(path, b"\xff\n")
        proc = run(["scan", path, "--json"])
        report = json.loads(proc.stdout)
        self.assertEqual(report["counts"]["files_scanned"], 1)
        self.assertEqual(report["counts"]["dirs_scanned"], 0)

    def test_determinism_byte_identical(self):
        write(os.path.join(self.root, "a.txt"), "x \n")
        write(os.path.join(self.root, "b.txt"), b"\xff\n")
        first = run(["scan", self.root, "--json"])
        second = run(["scan", self.root, "--json"])
        self.assertEqual(first.stdout, second.stdout)

    def test_read_only_tree_unchanged(self):
        path = os.path.join(self.root, "a.txt")
        write(path, "keep me \n")
        with open(path, "rb") as fh:
            before = fh.read()
        run(["scan", self.root])
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_version(self):
        proc = run(["--version"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
