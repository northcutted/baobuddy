#!/usr/bin/env python3
"""Compose every captured locale with the marketing compositor.

`bin/ios-release screenshots-compose` (`make process-screenshots`) runs this with the locked
image tools from scripts/requirements.txt. Raw captures are read from
app-store/screenshots-raw/<locale>/; each locale's app-store/screenshots/<locale>/ folder is
rebuilt from scratch, so a screen dropped from .github/ios-release.json leaves no stale file.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    config = json.loads((ROOT / '.github/ios-release.json').read_text())
    captures = ROOT / 'app-store/screenshots-raw'
    output = ROOT / config['screenshots_path']
    locales = sorted(path.name for path in captures.iterdir()
                     if path.is_dir() and path.name in config['locales'] and any(path.glob('*.png')))
    if not locales:
        raise ValueError('No captured locales to compose')
    output.mkdir(parents=True, exist_ok=True)
    # Validate and render before replacing any reviewed artwork. A partial capture
    # or a decoder failure must leave the existing set available.
    with tempfile.TemporaryDirectory(dir=output.parent) as temp:
        for locale in locales:
            subprocess.run([sys.executable, str(ROOT / 'scripts/process_screenshots.py'),
                            '--locale', locale, '--output-dir', temp], cwd=ROOT, check=True)
        for locale in locales:
            destination = output / locale
            destination.mkdir(exist_ok=True)
            rendered = list((Path(temp) / locale).glob('*.png'))
            stale = set(destination.glob('*.png')) - {destination / p.name for p in rendered}
            for path in rendered:
                path.replace(destination / path.name)
            for path in stale:
                path.unlink()


if __name__ == '__main__':
    main()
