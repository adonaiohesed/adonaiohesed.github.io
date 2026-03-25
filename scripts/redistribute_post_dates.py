#!/usr/bin/env python3
"""
Redistributes post dates across 2018-2025 for balanced chronological spread.
"""

import os
import re
from datetime import datetime, timedelta
from pathlib import Path
import shutil

def parse_post_date(filename):
    """Extract date from filename."""
    match = re.match(r'(\d{4})-(\d{2})-(\d{2})', filename)
    if match:
        return datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    return None

def get_post_slug(filename):
    """Extract slug from filename."""
    return filename[11:]  # Remove YYYY-MM-DD-

def read_frontmatter_and_content(filepath):
    """Read file and separate frontmatter from content."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Split on ---
    parts = content.split('---', 2)
    if len(parts) < 3:
        return None, content

    frontmatter = parts[1]
    body = parts[2]

    return frontmatter, body

def update_frontmatter_date(frontmatter, new_date):
    """Update date field in frontmatter."""
    # Replace existing date line
    date_pattern = r'date:\s*\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'
    new_date_str = new_date.strftime('%Y-%m-%d %H:%M:%S')

    if re.search(date_pattern, frontmatter):
        frontmatter = re.sub(date_pattern, f'date: {new_date_str}', frontmatter)
    else:
        # Add date if it doesn't exist
        frontmatter = frontmatter.rstrip() + f'\ndate: {new_date_str}'

    return frontmatter

def get_all_posts():
    """Get all posts with their current info."""
    posts_dir = Path('/Users/hyoeunchoi/Documents/adonaiohesed.github.io/_posts')
    posts = []

    for filepath in sorted(posts_dir.glob('*.md')):
        filename = filepath.name
        current_date = parse_post_date(filename)
        slug = get_post_slug(filename)

        posts.append({
            'filepath': filepath,
            'filename': filename,
            'current_date': current_date,
            'slug': slug
        })

    return posts

def generate_new_dates():
    """Generate balanced dates across 2018-2025."""
    # 200 posts across 8 years = 25 per year
    # Distribute with roughly 2-3 per month

    start_date = datetime(2018, 1, 1)
    end_date = datetime(2025, 12, 31)

    dates = []
    current = start_date
    interval = (end_date - start_date) / 200

    for i in range(200):
        dates.append(start_date + (interval * i))

    return sorted(dates)

def main():
    posts = get_all_posts()
    new_dates = generate_new_dates()

    print(f"Found {len(posts)} posts")
    print(f"Generated {len(new_dates)} new dates")

    # Create mapping
    updates = []
    for post, new_date in zip(posts, new_dates):
        old_filename = post['filename']
        new_filename = new_date.strftime('%Y-%m-%d-') + post['slug']
        updates.append({
            'old_filepath': post['filepath'],
            'old_filename': old_filename,
            'new_filename': new_filename,
            'new_date': new_date,
            'slug': post['slug']
        })

    # Show summary
    print("\nDate distribution changes:")
    print("Before:")
    for year in range(2018, 2026):
        count = sum(1 for p in posts if p['current_date'] and p['current_date'].year == year)
        if count > 0:
            print(f"  {year}: {count}")

    print("\nAfter:")
    for year in range(2018, 2026):
        count = sum(1 for u in updates if u['new_date'].year == year)
        if count > 0:
            print(f"  {year}: {count}")

    # Confirm before making changes
    response = input("\nProceed with date redistribution? (y/n): ").strip().lower()
    if response != 'y':
        print("Cancelled.")
        return

    # Update files
    posts_dir = Path('/Users/hyoeunchoi/Documents/adonaiohesed.github.io/_posts')

    for update in updates:
        old_path = update['old_filepath']
        new_path = posts_dir / update['new_filename']

        # Read and update content
        frontmatter, body = read_frontmatter_and_content(old_path)
        if frontmatter is None:
            print(f"Warning: Could not parse {update['old_filename']}")
            continue

        # Update frontmatter
        updated_frontmatter = update_frontmatter_date(frontmatter, update['new_date'])

        # Write new file
        new_content = f"---{updated_frontmatter}---{body}"
        with open(new_path, 'w', encoding='utf-8') as f:
            f.write(new_content)

        # Remove old file
        if old_path != new_path:
            old_path.unlink()

        print(f"✓ {update['old_filename']} → {update['new_filename']}")

    print(f"\n✓ Updated {len(updates)} posts")

if __name__ == '__main__':
    main()
