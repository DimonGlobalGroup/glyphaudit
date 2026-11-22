# GlyphAudit

A read-only, deterministic text-file encoding and hygiene auditor in
a single Python file. GlyphAudit walks one or more roots, classifies
binary files honestly and skips them, decodes the rest as strict
UTF-8 itself so encoding failures are measured with a byte offset,
and reports encoding, line-ending, and whitespace findings under
named rules — it never modifies anything.

Text trees rot invisibly. A file saved as UTF-16 by one editor, a
stray invalid byte from a bad copy, CRLF and LF endings mixed by two
tools, a control character pasted in from a terminal — none of these
show up in a normal listing, and all of them surface later as
mojibake, broken parsers, or diffs nobody can explain. The usual
answers are whitespace *fixers* that rewrite your files, or linters
that need a config file before they will say anything. GlyphAudit
makes the audit visible and reproducible first, so a human can
decide what — if anything — to change.

## Why it's different

- **Encoding is the product.** Whitespace linters stop at spaces.
  GlyphAudit's headline rules are the failures that corrupt data in
  transit: bytes that are not valid UTF-8 (with the offset of the
  first bad byte and its line), a UTF-16 byte-order mark on a file
  everyone treats as UTF-8, and control characters hiding in text.
- **Read-only by construction.** No `--fix`, no normalize mode, no
  writes of any kind. It reports; you decide. That makes it safe to
  run against a tree you do not own yet — an incoming restore, a
  release tree, someone else's export.
- **Binary honesty.** A file containing a NUL byte is classified as
  binary, counted, and skipped — never decoded by force and never
  reported as clean text.
- **Per-line, gate-shaped output.** Every finding carries its line
  number. Severity thresholds and exit codes are designed for gates,
  and repeated `--json` runs are byte-identical, so output diffs
  cleanly in CI and in code review.
- **No config required.** Sensible defaults audit a tree as-is;
  `--extensions` and `--max-line` tune the scan when you need them.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `invalid-utf8` | high | Bytes (after any BOM) are not valid UTF-8; detail gives the first bad byte's offset |
| `control-char` | medium | A line contains a control character (below U+0020, tab excepted, or U+007F); one finding per line |
| `cr-only` | medium | The file uses at least one lone-CR line ending |
| `mixed-line-endings` | medium | The file uses more than one line-ending type (CRLF / LF / lone CR) |
| `utf16-bom` | medium | The file starts with a UTF-16 byte-order mark |
| `bom-present` | low | The file starts with a UTF-8 byte-order mark |
| `long-line` | low | A line exceeds `--max-line` characters |
| `mixed-indent` | low | The file mixes tab-indented and space-indented lines |
| `no-final-newline` | low | A non-empty file does not end with a newline |
| `trailing-whitespace` | low | A line ends with a space or tab |

One file can produce several findings. A UTF-16 BOM or an invalid
UTF-8 failure ends that file's analysis (the finding is the
diagnosis); a UTF-8 BOM is reported and stripped, and the remaining
content is audited normally.

## Install

Nothing to install. Python 3.10+ and its standard library only.

```sh
python3 glyphaudit.py --version
```

## Usage

```sh
python3 glyphaudit.py scan PATH [PATH ...] [--json] \
    [--min-severity low|medium|high] \
    [--fail-on low|medium|high|never] \
    [--max-line N] [--extensions .txt,.md]
```

Each PATH may be a regular file or a directory; directories are
walked recursively in sorted order. Symlinks are counted and never
followed or opened. Defaults: `--max-line 200`, `--fail-on high`:
the scan exits 1 when any finding is at or above that severity.
`--min-severity` filters what is reported, counted, and considered
for the exit decision.

### Example

A tree with a clean file, a file containing an invalid byte, a file
mixing CRLF and LF endings, and a file with trailing whitespace and
no final newline:

```text
$ python3 glyphaudit.py scan /tmp/ga-demo
HIGH invalid-utf8 1 /tmp/ga-demo/broken.txt offset 4
LOW trailing-whitespace 1 /tmp/ga-demo/messy.txt
LOW no-final-newline 2 /tmp/ga-demo/messy.txt
MEDIUM mixed-line-endings 2 /tmp/ga-demo/mixed.txt
glyphaudit: 1 dirs scanned, 4 files, 4 findings (1 high, 1 medium, 2 low), 0 binary skipped, 0 errors
```

Exit code is 1 because an `invalid-utf8` (high) finding meets the
default `--fail-on high` threshold.

## Exit codes

- `0` — scan completed; no finding at or above `--fail-on`.
- `1` — at least one finding at or above `--fail-on`.
- `2` — usage error or a scan root that is missing, or neither a
  regular file nor a directory.

## Limitations

- GlyphAudit judges bytes and lines, not meaning: it cannot tell
  whether a long line is a wrapped paragraph or a data record, only
  that it exceeds the limit you set.
- Valid UTF-8 in the wrong language encoding (for example,
  Windows-1252 bytes that happen to decode) is not detectable by
  decoding alone and is not claimed.
- Files are read fully into memory; the tool is built for source,
  document, and export trees, not for multi-gigabyte logs.

## License

MIT — see `LICENSE`. Copyright (c) 2026 Dimon Global Group.
