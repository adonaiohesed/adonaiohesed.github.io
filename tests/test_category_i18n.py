"""Build small real Jekyll archives to check language previews and fallbacks."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class CategoryLanguageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        # Use the actual templates, including their real Jekyll include scope.
        script = r'''
require 'jekyll'
require 'jekyll-archives'
require 'nokogiri'
require 'fileutils'
require 'json'
root, fixture = ARGV
%w[_layouts _includes _data _posts].each { |dir| FileUtils.mkdir_p(File.join(fixture, dir)) }
FileUtils.cp(File.join(root, '_layouts/category.html'), File.join(fixture, '_layouts/category.html'))
%w[category-name.html bilingual-post-text.html].each do |name|
  FileUtils.cp(File.join(root, '_includes', name), File.join(fixture, '_includes', name))
end
FileUtils.cp(File.join(root, '_data/category_locales.yml'), File.join(fixture, '_data/category_locales.yml'))
File.write(File.join(fixture, '_layouts/default.html'), "<!doctype html><html><body>{{ content }}</body></html>")
posts = {
  '2000-01-05-featured.md' => ['English featured', true, "## English heading\n\nEnglish intro only.\n\n---\n\n## 한국어 *대표* 제목\n\n한국어 대표 요약이다.\n\n---\n\n두 번째 한국어 구간도 보존한다.\n"],
  '2000-01-04-nested.md' => ['English nested & title', true, "## English & section\n\nEnglish & summary.\n\n---\n\n## 한국어 **중첩** & 제목\n\n한국어 & 중첩 요약이다.\n"],
  '2000-01-03-plain.md' => ['Original fallback', false, "## 원래 본문\n\n원래 단일 언어 요약이다.\n"],
  '2000-01-02-no-separator.md' => ['Missing separator fallback', true, "## 분리선 없는 본문\n\n다른 글의 번역을 가져오지 않는다.\n"],
  '2000-01-01-no-heading.md' => ['Heading fallback', true, "English paragraph.\n\n---\n\n제목 없는 한국어 요약이다.\n"]
}
posts.each do |name, (title, bilingual, body)|
  File.write(File.join(fixture, '_posts', name), "---\ntitle: #{title}\nbilingual: #{bilingual}\ncategories: [Engineering]\n---\n#{body}")
end
config = Jekyll.configuration('source' => fixture, 'destination' => File.join(fixture, '_site'),
  'quiet' => true, 'disable_disk_cache' => true, 'plugins' => ['jekyll-archives'],
  'defaults' => [{'scope' => {'type' => 'posts'}, 'values' => {'permalink' => '/posts/:title/'}}],
  'jekyll-archives' => {'enabled' => ['categories'], 'layouts' => {'category' => 'category'},
    'permalinks' => {'category' => '/categories/:name/'}})
Jekyll::Site.new(config).process
doc = Nokogiri::HTML(File.read(File.join(fixture, '_site/categories/engineering/index.html')))
text = ->(node, selector) { node.at_css(selector)&.text&.split&.join(' ') }
cards = doc.css('.cat-featured-card, .post-card').map do |card|
  title = card.at_css('.cat-featured-title, .post-title')
  excerpt = card.at_css('.cat-featured-excerpt, .post-excerpt')
  {'url' => card['href'], 'en_title' => text.call(title, '[data-lang=en]'),
   'kr_title' => text.call(title, '[data-lang=kr]'), 'en_excerpt' => text.call(excerpt, '[data-lang=en]'),
   'kr_excerpt' => text.call(excerpt, '[data-lang=kr]')}
end
puts JSON.generate({'hero_kr' => text.call(doc, '.cat-hero-title [data-lang=kr]'),
  'description_kr' => text.call(doc, '.cat-hero-desc [data-lang=kr]'),
  'read_kr' => text.call(doc, '.cat-featured-readmore [data-lang=kr]'), 'cards' => cards})
'''
        result = subprocess.run(['bundle', 'exec', 'ruby', '-e', script, str(ROOT), cls.temp.name],
                                cwd=ROOT, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)
        cls.data = json.loads(result.stdout)
        cls.cards = {card['url']: card for card in cls.data['cards']}

    def test_localizes_archive_and_featured_post(self):
        self.assertEqual(self.data['hero_kr'], '엔지니어링')
        self.assertIn('시스템 설계', self.data['description_kr'])
        self.assertEqual(self.data['read_kr'], '글 읽기')
        featured = self.cards['/posts/featured/']
        self.assertEqual(featured['en_title'], 'English featured')
        self.assertEqual(featured['kr_title'], '한국어 대표 제목')
        self.assertIn('한국어 대표 요약이다.', featured['kr_excerpt'])
        self.assertIn('두 번째 한국어 구간', featured['kr_excerpt'])
        self.assertNotIn('English intro', featured['kr_excerpt'])

    def test_preserves_nested_headings_and_independent_fallbacks(self):
        nested = self.cards['/posts/nested/']
        self.assertEqual(nested['kr_title'], '한국어 중첩 & 제목')
        self.assertEqual(nested['en_title'], 'English nested & title')
        self.assertIn('한국어 & 중첩 요약', nested['kr_excerpt'])
        self.assertIn('English & section', nested['en_excerpt'])
        plain = self.cards['/posts/plain/']
        self.assertEqual(plain['kr_title'], plain['en_title'])
        self.assertEqual(plain['kr_excerpt'], plain['en_excerpt'])
        missing = self.cards['/posts/no-separator/']
        self.assertEqual(missing['kr_title'], 'Missing separator fallback')
        self.assertEqual(missing['kr_excerpt'], missing['en_excerpt'])
        no_heading = self.cards['/posts/no-heading/']
        self.assertEqual(no_heading['kr_title'], 'Heading fallback')
        self.assertIn('제목 없는 한국어 요약', no_heading['kr_excerpt'])


if __name__ == '__main__':
    unittest.main()
