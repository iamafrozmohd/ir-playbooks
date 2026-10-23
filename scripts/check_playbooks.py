#!/usr/bin/env python3
"""Structure and link checks for the IR playbooks.

Every playbook must follow the same layout so an analyst can find the same
section in the same place under pressure. This script fails CI when:
  - a playbook is missing a required section, or has them out of order
  - a playbook has no ATT&CK mapping, malformed technique IDs, or no decision flow
  - any Markdown file links to a local file or #anchor that doesn't exist
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAYBOOK_DIR = ROOT / "playbooks"

REQUIRED_SECTIONS = [
    "Overview",
    "Triggers",
    "ATT&CK mapping",
    "Severity",
    "Decision flow",
    "1. Detection and analysis",
    "2. Containment",
    "3. Eradication",
    "4. Recovery",
    "5. Post-incident activity",
    "Hunting queries",
    "Analyst checklist",
]

TECHNIQUE_CELL = re.compile(r"^\|.*\|\s*(T\S*)\s*\|\s*$")
VALID_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*$")


def slugify(heading: str) -> str:
    """GitHub-style anchor for a heading."""
    text = re.sub(r"[`*_]", "", heading).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def strip_code(text: str) -> str:
    """Remove fenced code blocks so links and headings inside them are ignored."""
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL)


def anchors(path: Path) -> set:
    return {
        slugify(m.group(2))
        for line in strip_code(path.read_text(encoding="utf-8")).splitlines()
        if (m := HEADING.match(line))
    }


def check_playbook(path: Path) -> list:
    errors = []
    text = path.read_text(encoding="utf-8")
    body = strip_code(text)
    h2 = [m.group(2) for line in body.splitlines() if (m := HEADING.match(line)) and len(m.group(1)) == 2]

    missing = [s for s in REQUIRED_SECTIONS if s not in h2]
    if missing:
        errors.append(f"missing sections: {', '.join(missing)}")
    else:
        order = [s for s in h2 if s in REQUIRED_SECTIONS]
        if order != REQUIRED_SECTIONS:
            errors.append("required sections are out of order")

    if not body.lstrip().startswith("# Playbook: "):
        errors.append("first line must be '# Playbook: <name>'")
    if "```mermaid" not in text:
        errors.append("no mermaid decision-flow diagram")

    in_attack = False
    ids = []
    for line in body.splitlines():
        if line.startswith("## "):
            in_attack = line == "## ATT&CK mapping"
            continue
        if in_attack and (m := TECHNIQUE_CELL.match(line)) and m.group(1) != "ID":
            ids.append(m.group(1))
    if not ids:
        errors.append("ATT&CK mapping table has no technique IDs")
    errors += [f"malformed ATT&CK ID: {t}" for t in ids if not VALID_TECHNIQUE.match(t)]

    if "- [ ]" not in body:
        errors.append("analyst checklist has no checkbox items")
    return errors


def check_links(path: Path) -> list:
    errors = []
    for target in LINK.findall(strip_code(path.read_text(encoding="utf-8"))):
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            continue  # external link (https:, mailto:)
        file_part, _, anchor = target.partition("#")
        dest = (path.parent / file_part).resolve() if file_part else path
        if not dest.exists():
            errors.append(f"broken link: {target}")
        elif anchor and dest.suffix == ".md" and anchor not in anchors(dest):
            errors.append(f"broken anchor: {target}")
    return errors


def main() -> int:
    playbooks = sorted(PLAYBOOK_DIR.glob("*.md"))
    if not playbooks:
        print("no playbooks found")
        return 1

    failed = False
    for md in sorted(ROOT.rglob("*.md")):
        errors = check_links(md)
        if md.parent == PLAYBOOK_DIR:
            errors = check_playbook(md) + errors
        rel = md.relative_to(ROOT)
        if errors:
            failed = True
            for e in errors:
                print(f"FAIL {rel}: {e}")
        else:
            print(f"ok   {rel}")

    print(f"\n{len(playbooks)} playbooks checked")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
