"""Regression checks for post metadata and publication; no network calls."""

from contextlib import redirect_stdout
from datetime import date
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))
from publish_scheduled_posts import publish_posts
from update_thumbnails import update_posts, update_thumbnail


class ThumbnailTests(unittest.TestCase):
    def test_preserves_body_and_other_metadata(self):
        body = '\n```yaml\nimage: my-app:v1\n```\nPhysical image: original text\n---\n끝\n'
        content = '---\ntitle: Test\nimage: old.png\nauthor: hyoeun\n---\n' + body
        result = update_thumbnail(content, '/assets/new.png')
        self.assertEqual(result, content.replace('image: old.png', 'image: "/assets/new.png"'))
        self.assertTrue(result.endswith(body))

    def test_adds_missing_metadata_even_if_body_has_image(self):
        content = '---\ntitle: Test\n---\nimage: my-app:v1\n'
        self.assertEqual(update_thumbnail(content, '/new.png'),
                         '---\ntitle: Test\nimage: "/new.png"\n---\nimage: my-app:v1\n')

    def test_preserves_crlf_and_is_idempotent(self):
        content = '---\r\ntitle: Test\r\n---\r\nBody\r\n'
        updated = update_thumbnail(content, '/new.png')
        self.assertEqual(updated, content.replace('title: Test\r\n',
                                                 'title: Test\r\nimage: "/new.png"\r\n'))
        self.assertEqual(update_thumbnail(updated, '/new.png'), updated)

    def test_rejects_missing_front_matter_and_nested_image(self):
        for content in ['Body only', '---\nimage:\n  path: old.png\n  alt: Keep me\n---\nBody']:
            with self.subTest(content=content), self.assertRaises(ValueError):
                update_thumbnail(content, '/new.png')

    def test_batch_validation_precedes_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / 'a.md'
            original = b'---\ntitle: A\nimage: old.png\n---\nBody'
            first.write_bytes(original)
            (root / 'z.md').write_text('Invalid post')
            with self.assertRaises(ValueError):
                update_posts(root)
            self.assertEqual(first.read_bytes(), original)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pending = self.root / '_pending_posts'
        self.posts = self.root / '_posts'
        self.pending.mkdir()
        self.posts.mkdir()

    def test_moves_due_posts_only_and_keeps_documentation(self):
        for name in ['2026-04-01-old.md', '2026-11-06-today.md', '2026-11-07-future.md', 'README.md']:
            (self.pending / name).write_bytes(b'original\r\nbody\n')
        with redirect_stdout(io.StringIO()):
            moved = publish_posts(self.root, date(2026, 11, 6))
        self.assertEqual(moved, 2)
        self.assertEqual(sorted(p.name for p in self.pending.iterdir()),
                         ['2026-11-07-future.md', 'README.md'])
        self.assertEqual((self.posts / '2026-11-06-today.md').read_bytes(), b'original\r\nbody\n')
        self.assertEqual(publish_posts(self.root, date(2026, 11, 6)), 0)

    def test_collision_preserves_entire_batch(self):
        (self.pending / '2026-01-01-first.md').write_text('first')
        (self.pending / '2026-01-02-collision.md').write_text('draft')
        existing = self.posts / '2026-01-02-collision.md'
        existing.write_text('published')
        with self.assertRaises(FileExistsError):
            publish_posts(self.root, date(2026, 11, 6))
        self.assertEqual(existing.read_text(), 'published')
        self.assertTrue((self.pending / '2026-01-01-first.md').exists())
        self.assertTrue((self.pending / existing.name).exists())
        self.assertFalse((self.posts / '2026-01-01-first.md').exists())

    def test_invalid_date_does_not_move_other_posts(self):
        (self.pending / '2026-01-01-valid.md').write_text('valid')
        (self.pending / '2026-02-30-invalid.md').write_text('invalid')
        with self.assertRaises(ValueError):
            publish_posts(self.root, date(2026, 11, 6))
        self.assertEqual(len(list(self.pending.iterdir())), 2)
        self.assertFalse(list(self.posts.iterdir()))

    def test_cli_emits_workflow_output(self):
        output = self.root / 'output'
        (self.pending / '2026-11-06-post.md').write_text('post')
        env = dict(os.environ, GITHUB_OUTPUT=str(output))
        result = subprocess.run([sys.executable, str(ROOT / 'scripts/publish_scheduled_posts.py'),
                                 '--root', str(self.root), '--today', '2026-11-06'],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(), 'moved=true\n')


class GeneratorTests(unittest.TestCase):
    def test_both_generators_round_trip_special_yaml_characters(self):
        anthropic = types.ModuleType('anthropic')
        anthropic.Anthropic = object
        topic = 'OAuth 2.0: "Security" # 한글 [A, B] \\ path\nNext line'
        category = 'Security: "Web", [API] # category'
        for filename, function in [('create_blog_post.py', 'create_blog_post'),
                                   ('create_blog_post_ai.py', 'create_blog_post_with_ai')]:
            with self.subTest(generator=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / '_posts').mkdir()
                with patch.dict(sys.modules, {'anthropic': anthropic}):
                    spec = importlib.util.spec_from_file_location('generator', ROOT / 'scripts' / filename)
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                module.__file__ = str(root / 'scripts' / filename)
                if filename.endswith('_ai.py'):
                    module.generate_blog_outline_with_ai = lambda *args: '## Test body\n'
                with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-placeholder'}), \
                     patch.object(module.subprocess, 'run'), redirect_stdout(io.StringIO()):
                    generated = getattr(module, function)(topic, category)
                # Parse with the same Ruby YAML implementation used by Jekyll.
                result = subprocess.run(['bundle', 'exec', 'ruby', '-e',
                    'require "yaml"; require "date"; require "json"; '
                    'text = File.read(ARGV[0]).split(/^---\\s*$\n?/, 3)[1]; '
                    'puts JSON.generate(YAML.safe_load(text, permitted_classes: [Date, Time]))',
                    generated], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                data = json.loads(result.stdout)
                self.assertEqual(data['title'], topic)
                self.assertEqual(data['tags'], [topic.lower()])
                self.assertEqual(data['categories'], [category])


if __name__ == '__main__':
    unittest.main()
