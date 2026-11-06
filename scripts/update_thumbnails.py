"""Update thumbnail metadata without changing post bodies."""

import json
from pathlib import Path
import re


def update_thumbnail(content, image_path):
    front_matter = re.match(r'\A---[ \t]*\r?\n(.*?)^---[ \t]*\r?$', content, re.M | re.S)
    if not front_matter:
        raise ValueError("Post must start with YAML front matter")

    metadata = front_matter.group(1)
    image = re.search(r'^image:[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*', metadata, re.M)
    replacement = f'image: {json.dumps(image_path, ensure_ascii=False)}'
    if image:
        # Do not discard nested metadata or YAML block scalars.
        if '\n' in image.group() or not image.group().partition(':')[2].strip():
            raise ValueError("Expected a single-line image field")
        metadata = metadata[:image.start()] + replacement + metadata[image.end():]
    else:
        newline = '\r\n' if '\r\n' in content else '\n'
        metadata += replacement + newline

    return content[:front_matter.start(1)] + metadata + content[front_matter.end(1):]


def update_posts(posts_directory=Path('_posts')):
    updates = []
    for post in sorted(Path(posts_directory).glob('*.md')):
        # Preserve original newline bytes as well as the Markdown body.
        content = post.read_bytes().decode('utf-8')
        updated = update_thumbnail(content, f'/assets/thumbnails/{post.stem}.png')
        if updated != content:
            updates.append((post, updated))

    for post, updated in updates:
        post.write_bytes(updated.encode('utf-8'))
    print(f"Updated {len(updates)} post thumbnail paths.")


if __name__ == '__main__':
    update_posts()
