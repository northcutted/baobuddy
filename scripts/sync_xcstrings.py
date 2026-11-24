#!/usr/bin/env python3
"""Sync the string catalogs with the strings in the code.

Xcode updates string catalogs when you build in the IDE, but `xcodebuild` doesn't write
them back, and nothing extracts the `BaoBuddyCore` table, because BaoBuddyCore and
BaoBuddySSH are SwiftPM targets. This script:

1. builds the BaoBuddy scheme for the iOS Simulator with SWIFT_EMIT_LOC_STRINGS=YES, and
   BaoBuddySSH (which builds BaoBuddyCore) with the compiler's `-emit-localized-strings`;
2. runs `xcstringstool sync`, the tool Xcode uses, on each catalog with its .stringsdata:

   BaoBuddy/Localizable.xcstrings              the app (table Localizable)
   BaoBuddyLiveActivity/Localizable.xcstrings  the Live Activity widget (table Localizable)
   BaoBuddy/BaoBuddyCore.xcstrings             Core and SSH strings the app shows (table BaoBuddyCore)

Sync adds new keys with the code's comment, removes keys that are no longer in the code and
have no translations, and keeps comments, plural variations and `shouldTranslate` set in the
catalog.

Core strings call `String(localized:table: "BaoBuddyCore")` and resolve from the app's main
bundle. The macOS helper and CLI ship no such table, so they print the English defaults.
The app compiles no Core source, so Xcode's own sync would treat every key in
BaoBuddyCore.xcstrings as stale; the keys are marked `extractionState: manual` to stop
that, and this script removes the ones the code no longer uses.

The InfoPlist catalogs are edited by hand.

Usage: scripts/sync_xcstrings.py [--derived-data DIR] [--skip-build]
"""
import argparse
import glob
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DESTINATION = 'generic/platform=iOS Simulator'


def run(cmd):
    print('+', ' '.join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True)


def stringsdata(directory, target):
    """The target's compiler-extracted .stringsdata, without generated symbol files."""
    pattern = f'{directory}/**/{target}.build/Objects-normal/*/*.stringsdata'
    files = sorted(glob.glob(pattern, recursive=True))
    files = [f for f in files if not Path(f).name.startswith(('Generated', 'Extracted'))]
    # One architecture is enough; the strings don't differ between them.
    arches = sorted({Path(f).parent.name for f in files})
    return [f for f in files if Path(f).parent.name == arches[0]] if arches else []


def sync(catalog, files):
    if not files:
        sys.exit(f'No .stringsdata for {catalog}; did the build run with string extraction?')
    run(['xcrun', 'xcstringstool', 'sync', catalog, '--stringsdata', *files])


def sync_core(catalog, files):
    """Sync the Core catalog, then mark its keys manual so Xcode's IDE sync keeps them."""
    path = ROOT / catalog
    data = json.loads(path.read_text(encoding='utf-8'))
    for entry in data['strings'].values():
        if entry.get('extractionState') == 'manual':
            del entry['extractionState']
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / path.name
        scratch.write_text(json.dumps(data, ensure_ascii=False), encoding='utf-8')
        sync(scratch, files)
        data = json.loads(scratch.read_text(encoding='utf-8'))
    for entry in data['strings'].values():
        if entry.get('extractionState') != 'stale':
            entry['extractionState'] = 'manual'
    write_catalog(path, data)


def write_catalog(path, data):
    """Write a catalog the way Xcode does: sorted keys, 2-space indent, ' : ' separators."""
    text = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True, separators=(',', ' : '))
    path.write_text(text + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--derived-data', default=str(ROOT / 'build' / 'loc'), help='build directory (default: build/loc)')
    parser.add_argument('--skip-build', action='store_true', help='reuse .stringsdata from an earlier run')
    args = parser.parse_args()

    derived = Path(args.derived_data).resolve()
    core_strings = derived / 'core-stringsdata'
    if not args.skip_build:
        run([
            'xcodebuild', 'build', '-project', 'BaoBuddy.xcodeproj', '-scheme', 'BaoBuddy',
            '-destination', DESTINATION, '-derivedDataPath', derived / 'xcode',
            'CODE_SIGNING_ALLOWED=NO', 'SWIFT_EMIT_LOC_STRINGS=YES', '-quiet',
        ])
        shutil.rmtree(core_strings, ignore_errors=True)
        core_strings.mkdir(parents=True)
        # The compiler emits .stringsdata only for files it compiles, so rebuild both modules in full.
        for module in ('BaoBuddyCore', 'BaoBuddySSH'):
            # `<triple>/debug/<module>.build` (native build system) or `…/<module>-t.build` (Swift Build).
            for name in (f'{module}.build', f'{module}-t.build'):
                for stale in glob.glob(f'{derived}/swiftpm/**/{name}', recursive=True):
                    shutil.rmtree(stale)
        run([
            'swift', 'build', '--target', 'BaoBuddySSH', '--scratch-path', derived / 'swiftpm',
            '-Xswiftc', '-emit-localized-strings', '-Xswiftc', '-emit-localized-strings-path', '-Xswiftc', core_strings,
        ])

    sync('BaoBuddy/Localizable.xcstrings', stringsdata(derived / 'xcode', 'BaoBuddy'))
    sync('BaoBuddyLiveActivity/Localizable.xcstrings', stringsdata(derived / 'xcode', 'BaoBuddyLiveActivity'))
    # Only BaoBuddyCore and BaoBuddySSH sources call the BaoBuddyCore table; dependencies extract nothing.
    core_files = sorted(
        f for f in glob.glob(f'{core_strings}/*.stringsdata')
        if json.loads(Path(f).read_text(encoding='utf-8')).get('tables', {}).get('BaoBuddyCore')
    )
    sync_core('BaoBuddy/BaoBuddyCore.xcstrings', core_files)
    print('Catalogs synced.')


if __name__ == '__main__':
    main()
