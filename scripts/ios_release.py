#!/usr/bin/env python3
"""Run the pinned ios-release platform CLI locally (as PicStrip does); Actions supplies IOS_RELEASE_ROOT.

The reviewed platform commit is the one the release workflows already pin
(`platform_revision` in .github/workflows/main.yml), so there is one pin to update.
`bin/ios-release sync` fetches that commit once into build/ios-release-platform/;
every other command runs offline from there.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'northcutted/ios-release-workflows'


def pinned_revision():
    workflow = (ROOT / '.github/workflows/main.yml').read_text()
    revisions = set(re.findall(r'^\s*platform_revision:\s*([a-f0-9]{40})\s*$', workflow, re.MULTILINE))
    uses = set(re.findall(rf'uses:\s*{re.escape(REPOSITORY)}/\S+@([a-f0-9]{{40}})', workflow))
    if len(revisions) != 1 or revisions != uses:
        raise ValueError('Expected one full platform commit, the same in uses: and platform_revision: of main.yml')
    return revisions.pop()


def platform_root(revision, sync=False):
    # Set only by the pinned bootstrap action, or explicitly for platform development.
    if os.environ.get('IOS_RELEASE_ROOT') and not sync:
        result = Path(os.environ['IOS_RELEASE_ROOT']).resolve()
    else:
        cache = ROOT / 'build/ios-release-platform'
        result = cache / revision
        if sync and not result.exists():
            cache.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='fetch-', dir=cache) as temp:
                subprocess.run(['git', 'init', '-q', temp], check=True)
                subprocess.run(['git', '-C', temp, 'fetch', '--quiet', '--depth=1',
                                f'https://github.com/{REPOSITORY}.git', revision], check=True)
                subprocess.run(['git', '-C', temp, 'checkout', '--quiet', '--detach', 'FETCH_HEAD'], check=True)
                Path(temp).rename(result)
        if not result.is_dir():
            raise ValueError('Platform is not cached. Run make platform-sync once; subsequent commands work offline.')
        head = subprocess.check_output(['git', '-C', str(result), 'rev-parse', 'HEAD'], text=True).strip()
        dirty = subprocess.check_output(['git', '-C', str(result), 'status', '--porcelain', '--untracked-files=all'], text=True)
        if head != revision or dirty.strip():
            raise ValueError('Cached platform differs from the reviewed pin; inspect it before resyncing')
    if not (result / 'bin/ios-release').is_file():
        raise ValueError('Platform does not provide the supported command interface')
    return result


def main():
    args = sys.argv[1:]
    sync = args == ['sync']
    revision = pinned_revision()
    platform = platform_root(revision, sync or (args[:1] == ['setup'] and not os.environ.get('IOS_RELEASE_ROOT')))
    if sync:
        print(f'Pinned platform ready: {platform}')
        return 0
    env = {**os.environ, 'IOS_APP_ROOT': str(ROOT), 'IOS_RELEASE_CONFIG': str(ROOT / '.github/ios-release.json')}
    env.setdefault('IOS_RELEASE_REVISION', revision)
    head = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    if head.returncode == 0:
        env.setdefault('SOURCE_SHA', head.stdout.strip())
    return subprocess.call([sys.executable, str(platform / 'bin/ios-release'), *args], cwd=ROOT, env=env)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
