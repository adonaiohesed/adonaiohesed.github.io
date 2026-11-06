"""Exercise content-protection checks without changing any repository post."""

import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = '''---
title: Test
published: false
---
## 원래 제목

English prose stays exactly the same.

나는 3개의 API를 사용할 수도 있습니다. 거의 없습니다.

`print("코드입니다")`를 실행합니다.

[문서](https://example.com/v1)와 ![그림](image.png)을 봅니다.

> "안녕하세요. 메일 예문입니다."

```python
# 원래 코드 주석입니다.
version = 3
```

$$x = 2$$

---
'''


def compare(sources):
    result = subprocess.run([
        'bundle', 'exec', 'ruby', '-e',
        'require "json"; require ARGV[0]; '
        'pairs = JSON.parse(STDIN.read); '
        'puts JSON.generate(pairs.map { |a,b| EditorialPreservation.compare('
        '{"post.md" => EditorialPreservation.fingerprint(a)}, '
        '{"post.md" => EditorialPreservation.fingerprint(b)}) })',
        str(ROOT / 'tools/check_editorial_preservation.rb')],
        input=json.dumps(sources), text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        raise AssertionError(result.stderr)
    return json.loads(result.stdout)


class EditorialPreservationTests(unittest.TestCase):
    def test_accepts_korean_tone_changes(self):
        edited = SOURCE.replace('사용할 수도 있습니다', '사용할 수도 있다')
        edited = edited.replace('거의 없습니다', '거의 없다').replace('실행합니다', '실행한다')
        self.assertEqual(compare([[SOURCE, edited]]), [[]])

    def test_rejects_changed_protected_content(self):
        cases = {
            'front_matter': SOURCE.replace('published: false', 'published: true'),
            'code': SOURCE.replace('# 원래 코드 주석입니다.', '# 바뀐 주석이다.'),
            'inline_code': SOURCE.replace('print("코드입니다")', 'print("코드다")'),
            'english': SOURCE.replace('English prose', 'Different prose'),
            'number': SOURCE.replace('3개의 API', '4개의 API'),
            'heading': SOURCE.replace('원래 제목', '바뀐 제목'),
            'url': SOURCE.replace('example.com/v1', 'example.com/v2'),
            'link_label': SOURCE.replace('[문서]', '[다른 문서]'),
            'image': SOURCE.replace('image.png', 'other.png'),
            'math': SOURCE.replace('x = 2', 'x = 3'),
            'quotation': SOURCE.replace('메일 예문입니다.', '메일 예문이다.'),
            'structure': SOURCE.replace('## 원래 제목', '### 원래 제목'),
            'line_boundary': SOURCE.replace('거의 없습니다.', '거의\n없습니다.'),
        }
        failures = compare([[SOURCE, edited] for edited in cases.values()])
        for name, detected in zip(cases, failures):
            with self.subTest(protection=name):
                self.assertTrue(detected, f'Failed to reject {name} change')

    def test_rejects_deleted_post(self):
        result = subprocess.run([
            'bundle', 'exec', 'ruby', '-e',
            'require "json"; require ARGV[0]; '
            'puts JSON.generate(EditorialPreservation.compare({"post.md" => {}}, {}))',
            str(ROOT / 'tools/check_editorial_preservation.rb')],
            text=True, capture_output=True, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Post filenames changed', json.loads(result.stdout))


if __name__ == '__main__':
    unittest.main()
