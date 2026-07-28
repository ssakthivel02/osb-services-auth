#!/usr/bin/env python3
"""Conservative repository secret scanner with low false-positive behaviour."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {'.git', '.venv', 'node_modules', '__pycache__'}
TEXT_SUFFIXES = {'.py', '.yml', '.yaml', '.json', '.md', '.txt', '.toml', '.ini', '.env', '.sh'}
PEM = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
ASSIGNMENT = re.compile(
    r'(?i)\b(client_secret|api[_-]?key|password|private[_-]?key)\b\s*[:=]\s*["\']([^"\']{12,})["\']'
)
PLACEHOLDER_MARKERS = ('example', 'placeholder', 'changeme', '${', '{{', '<', 'redacted', 'dummy', 'test-only')


def candidate_files():
    for path in ROOT.rglob('*'):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name.startswith('.env'):
            yield path


def main() -> int:
    findings: list[str] = []
    for path in candidate_files():
        try:
            text = path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            continue
        if PEM.search(text):
            findings.append(f'{path.relative_to(ROOT)}: private key block')
        for match in ASSIGNMENT.finditer(text):
            value = match.group(2).strip().lower()
            if any(marker in value for marker in PLACEHOLDER_MARKERS):
                continue
            findings.append(f'{path.relative_to(ROOT)}: suspicious literal for {match.group(1)}')
    if findings:
        print('Potential committed secret material detected:')
        for item in findings:
            print(f'- {item}')
        return 1
    print('Secret scan passed.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
