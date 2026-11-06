"""Publish due posts after checking the entire batch for name collisions."""

import argparse
from datetime import date, datetime
import os
from pathlib import Path
import re
from zoneinfo import ZoneInfo


def publish_posts(root, today):
    root = Path(root)
    pending = root / '_pending_posts'
    posts = root / '_posts'
    eligible = []

    for source in sorted(pending.glob('*.md')):
        match = re.fullmatch(r'(\d{4}-\d{2}-\d{2})-.+\.md', source.name)
        if not match:
            continue  # README.md is documentation, not a scheduled post.
        scheduled = date.fromisoformat(match.group(1))
        if scheduled <= today:
            target = posts / source.name
            if target.exists() or target.is_symlink():
                raise FileExistsError(f'Refusing to overwrite published post: {target}')
            eligible.append((source, target))

    posts.mkdir(exist_ok=True)
    for source, target in eligible:
        # Exclusive creation also prevents an overwrite if a file appears after preflight.
        with target.open('xb') as output:
            try:
                output.write(source.read_bytes())
            except BaseException:
                target.unlink()
                raise
        source.unlink()
        print(f'Published: {target.name}')
    return len(eligible)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--today', type=date.fromisoformat,
                        default=datetime.now(ZoneInfo('America/Chicago')).date())
    args = parser.parse_args()
    moved = publish_posts(args.root, args.today)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write(f'moved={str(moved > 0).lower()}\n')
    print(f'Published {moved} scheduled posts through {args.today}.')


if __name__ == '__main__':
    main()
