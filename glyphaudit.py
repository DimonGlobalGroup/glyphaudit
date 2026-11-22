#!/usr/bin/env python3
"""GlyphAudit — a read-only text-file encoding and hygiene auditor.

Audits every text file under one or more roots: classifies binary
files and skips them, decodes the rest as strict UTF-8 itself so
encoding failures are measured with a byte offset, and reports
encoding, line-ending, and whitespace findings under named rules
with a stable text or JSON report. It never modifies anything.
"""
import argparse
import json
import os
import sys

VERSION = "1.0.0"
TOOL = "glyphaudit"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

UTF8_BOM = b"\xef\xbb\xbf"
UTF16_LE_BOM = b"\xff\xfe"
UTF16_BE_BOM = b"\xfe\xff"


def make_finding(path, rule, severity, line, detail=""):
    return {
        "path": path,
        "rule": rule,
        "severity": severity,
        "line": line,
        "detail": detail,
    }


def line_of_offset(data, offset):
    """1-based line number of a byte offset (lines split on LF)."""
    return data[:offset].count(b"\n") + 1


def scan_endings(body):
    """Return (list of (line_no, kind) in order, first_cr_only_line).

    kind is 'CRLF', 'LF', or 'CR'. Lines are numbered by the ending's
    position: the first ending terminates line 1, and so on.
    """
    endings = []
    i = 0
    line = 1
    n = len(body)
    while i < n:
        byte = body[i]
        if byte == 0x0D:  # CR
            if i + 1 < n and body[i + 1] == 0x0A:
                endings.append((line, "CRLF"))
                i += 2
            else:
                endings.append((line, "CR"))
                i += 1
            line += 1
        elif byte == 0x0A:  # LF
            endings.append((line, "LF"))
            i += 1
            line += 1
        else:
            i += 1
    return endings


def audit_bytes(path, data, max_line):
    """Audit one file's bytes. Returns (findings, is_binary)."""
    findings = []
    if data.startswith(UTF16_LE_BOM) or data.startswith(UTF16_BE_BOM):
        detail = "utf-16-le" if data.startswith(UTF16_LE_BOM) else "utf-16-be"
        findings.append(make_finding(path, "utf16-bom", "medium", 1, detail))
        return findings, False
    if b"\x00" in data:
        return findings, True
    body = data
    bom_len = 0
    if body.startswith(UTF8_BOM):
        findings.append(make_finding(path, "bom-present", "low", 1, ""))
        body = body[len(UTF8_BOM):]
        bom_len = len(UTF8_BOM)
    try:
        text = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        offset = bom_len + exc.start
        findings.append(make_finding(
            path, "invalid-utf8", "high",
            line_of_offset(data, offset), "offset %d" % offset))
        return findings, False

    # Line endings, measured on the (BOM-stripped) bytes.
    endings = scan_endings(body)
    kinds_seen = []
    mixed_line = None
    first_cr_line = None
    for line_no, kind in endings:
        if kind == "CR" and first_cr_line is None:
            first_cr_line = line_no
        if kind not in kinds_seen:
            if kinds_seen and mixed_line is None:
                mixed_line = line_no
            kinds_seen.append(kind)
    if first_cr_line is not None:
        findings.append(make_finding(path, "cr-only", "medium", first_cr_line, ""))
    if mixed_line is not None:
        findings.append(make_finding(path, "mixed-line-endings", "medium", mixed_line, ""))

    # Split into content lines (ending excluded). A trailing ending
    # produces a phantom final element that is not a line.
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "" and text.endswith("\n"):
        raw_lines = raw_lines[:-1]
    lines = [ln[:-1] if ln.endswith("\r") else ln for ln in raw_lines]

    first_indent_kind = None
    mixed_indent_line = None
    for idx, line in enumerate(lines, start=1):
        if line.endswith((" ", "\t")) and line != "":
            findings.append(make_finding(path, "trailing-whitespace", "low", idx, ""))
        if len(line) > max_line:
            findings.append(make_finding(
                path, "long-line", "low", idx, "%d chars" % len(line)))
        for ch in line:
            code = ord(ch)
            if (code < 0x20 and ch != "\t") or code == 0x7F:
                findings.append(make_finding(
                    path, "control-char", "medium", idx, "U+%04X" % code))
                break
        if line.startswith("\t"):
            kind = "tab"
        elif line.startswith(" "):
            kind = "space"
        else:
            kind = None
        if kind is not None:
            if first_indent_kind is None:
                first_indent_kind = kind
            elif kind != first_indent_kind and mixed_indent_line is None:
                mixed_indent_line = idx
    if mixed_indent_line is not None:
        findings.append(make_finding(
            path, "mixed-indent", "low", mixed_indent_line, "tabs and spaces"))

    if data and not data.endswith((b"\n", b"\r")):
        findings.append(make_finding(
            path, "no-final-newline", "low", max(1, len(lines)), ""))
    return findings, False


def audit_file(path, max_line):
    with open(path, "rb") as fh:
        data = fh.read()
    return audit_bytes(path, data, max_line)


def collect_files(roots, extensions):
    """Walk roots. Returns (files, dirs_scanned, links_skipped, errors)."""
    files = []
    dirs_scanned = 0
    links_skipped = 0
    errors = 0

    def wanted(filename):
        if extensions is None:
            return True
        return os.path.splitext(filename)[1].lower() in extensions

    for root in roots:
        if os.path.islink(root):
            links_skipped += 1
            continue
        if os.path.isfile(root):
            if wanted(root):
                files.append(root)
            continue
        def _onerror(_err):
            nonlocal errors
            errors += 1

        for dirpath, dirnames, filenames in os.walk(
                root, topdown=True, onerror=_onerror, followlinks=False):
            dirs_scanned += 1
            dirnames.sort()
            filenames = sorted(filenames)
            kept_dirs = []
            for dirname in dirnames:
                full = os.path.join(dirpath, dirname)
                if os.path.islink(full):
                    links_skipped += 1
                else:
                    kept_dirs.append(dirname)
            dirnames[:] = kept_dirs
            for filename in filenames:
                full = os.path.join(dirpath, filename)
                if os.path.islink(full):
                    links_skipped += 1
                    continue
                if not os.path.isfile(full):
                    continue
                if wanted(filename):
                    files.append(full)
    return files, dirs_scanned, links_skipped, errors


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog=TOOL, description="Read-only text-file encoding and hygiene auditor.")
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Audit files and directories")
    scan.add_argument("paths", nargs="+", help="Files or directories to audit")
    scan.add_argument("--json", action="store_true", help="Emit a JSON report")
    scan.add_argument("--min-severity", choices=["low", "medium", "high"], default="low")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "never"], default="high")
    scan.add_argument("--max-line", type=int, default=200)
    scan.add_argument("--extensions", default=None,
                      help="Comma-separated suffix filter, e.g. .txt,.md")
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2
    if args.max_line < 1:
        print("%s: --max-line must be >= 1" % TOOL, file=sys.stderr)
        return 2
    extensions = None
    if args.extensions:
        extensions = set()
        for part in args.extensions.split(","):
            part = part.strip().lower()
            if not part:
                continue
            if not part.startswith("."):
                part = "." + part
            extensions.add(part)
        if not extensions:
            print("%s: --extensions names no suffix" % TOOL, file=sys.stderr)
            return 2

    for root in args.paths:
        if os.path.islink(root):
            continue
        if not (os.path.isfile(root) or os.path.isdir(root)):
            print("%s: scan root is not a file or directory: %s" % (TOOL, root),
                  file=sys.stderr)
            return 2

    files, dirs_scanned, links_skipped, walk_errors = collect_files(args.paths, extensions)
    all_findings = []
    files_scanned = 0
    files_skipped_binary = 0
    errors = walk_errors
    for path in files:
        try:
            findings, is_binary = audit_file(path, args.max_line)
        except OSError:
            errors += 1
            continue
        if is_binary:
            files_skipped_binary += 1
            continue
        files_scanned += 1
        all_findings.extend(findings)

    threshold = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in all_findings if SEVERITY_ORDER[f["severity"]] >= threshold]
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    counts = {
        "dirs_scanned": dirs_scanned,
        "files_scanned": files_scanned,
        "files_skipped_binary": files_skipped_binary,
        "links_skipped": links_skipped,
        "errors": errors,
        "findings": len(findings),
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
    }

    if args.json:
        report = {
            "tool": TOOL,
            "version": VERSION,
            "roots": args.paths,
            "counts": counts,
            "findings": findings,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for f in findings:
            line = "%s %s %d %s" % (
                f["severity"].upper(), f["rule"], f["line"], f["path"])
            if f["detail"]:
                line += " " + f["detail"]
            print(line)
        print("%s: %d dirs scanned, %d files, %d findings "
              "(%d high, %d medium, %d low), %d binary skipped, %d errors" % (
                  TOOL, counts["dirs_scanned"], counts["files_scanned"],
                  counts["findings"], counts["high"], counts["medium"],
                  counts["low"], counts["files_skipped_binary"], counts["errors"]))

    if args.fail_on == "never":
        return 0
    fail_threshold = SEVERITY_ORDER[args.fail_on]
    for f in findings:
        if SEVERITY_ORDER[f["severity"]] >= fail_threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
