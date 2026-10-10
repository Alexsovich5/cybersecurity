"""Checks that README.md matches the repository it describes."""
import os
import re
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
README = os.path.join(REPO, "README.md")
MAKEFILE = os.path.join(REPO, "Makefile")

FORBIDDEN_PREFIXES = ("**Organization**", "**Role**", "**Duration**", "**Project**")
PERCENT = re.compile(r"\b\d+(\.\d+)?%")
MAKE_TARGET = re.compile(r"\bmake ([a-z][a-z0-9-]*)")


def readme_lines():
    with open(README) as handle:
        return handle.read().splitlines()


def split_fenced(lines):
    """Return (prose lines, list of fenced blocks as (heading, lines))."""
    prose, blocks = [], []
    heading, current = None, None
    for line in lines:
        if line.startswith("```"):
            if current is None:
                current = []
            else:
                blocks.append((heading, current))
                current = None
            continue
        if current is not None:
            current.append(line)
            continue
        if line.startswith("## "):
            heading = line[3:].strip()
        prose.append(line)
    assert current is None, "unterminated code block"
    return prose, blocks


def layout_paths():
    _, blocks = split_fenced(readme_lines())
    layouts = [body for heading, body in blocks if heading == "Layout"]
    assert len(layouts) == 1, "expected exactly one code block under ## Layout"
    paths, stack = set(), []
    for line in layouts[0]:
        if not line.strip():
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        assert indent % 2 == 0, "odd indentation in layout: %r" % line
        depth = indent // 2
        assert depth <= len(stack), "layout skips a level: %r" % line
        del stack[depth:]
        if stripped.endswith("/"):
            stack.append(stripped[:-1])
        else:
            paths.add("/".join(stack + [stripped]))
    return paths


def git_files():
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=REPO
    ).decode()
    return set(line for line in output.splitlines() if line)


def makefile_targets():
    targets = set()
    with open(MAKEFILE) as handle:
        for line in handle:
            match = re.match(r"^([A-Za-z0-9_-]+)\s*:(?!=)", line)
            if match:
                targets.add(match.group(1))
    return targets


def test_layout_matches_git_files():
    layout = layout_paths()
    files = git_files()
    assert sorted(files - layout) == [], "files missing from README layout"
    assert sorted(layout - files) == [], "README layout lists files that do not exist"


def test_no_forbidden_prose():
    prose, _ = split_fenced(readme_lines())
    bad = []
    for line in prose:
        if line.lstrip().startswith(FORBIDDEN_PREFIXES):
            bad.append(line)
        elif "Developed during" in line or "img.shields.io" in line:
            bad.append(line)
        elif PERCENT.search(line):
            bad.append(line)
    assert bad == []


def test_template_comment_removed():
    text = "\n".join(readme_lines())
    assert "<!--" not in text
    assert "{{" not in text


def test_make_targets_exist():
    named = set()
    for line in readme_lines():
        named.update(MAKE_TARGET.findall(line))
    assert named, "README names no make targets"
    assert sorted(named - makefile_targets()) == []
