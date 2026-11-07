#!/usr/bin/env ruby
# Check behavior that HTML-Proofer cannot infer from JSON or language toggles.
require 'json'
require 'nokogiri'
require 'pathname'
require 'uri'
require 'yaml'
require 'date'

root = Pathname.new(ARGV.fetch(0, '_site')).expand_path
source = Pathname.new(__dir__).parent
documents = {}
read_document = lambda do |file|
  documents[file] ||= Nokogiri::HTML(file.read)
end

entries = JSON.parse(root.join('search.json').read)
entries.each do |entry|
  raise "Missing Korean search title: #{entry['url']}" if entry['title_kr'].to_s.strip.empty?
  %w[category_kr date_kr].each do |field|
    raise "Missing search field #{field}: #{entry['url']}" unless entry[field].is_a?(String)
  end
  uri = URI.parse(entry.fetch('url'))
  raise "Search result must be local: #{uri}" if uri.host || uri.scheme
  file = root.join(uri.path.delete_prefix('/'))
  file = file.join('index.html') if file.directory?
  raise "Missing search destination: #{uri}" unless file.file?
  document = read_document.call(file)
  raise "Empty search destination: #{uri}" if document.at_css('body')&.text.to_s.strip.empty?
  if uri.fragment
    matches = document.xpath('//*[@id=$id]', nil, id: uri.fragment)
    raise "Search anchor must identify one item: #{uri}" unless matches.size == 1
  end
end

collection_entries = entries.select { |entry| %w[Project CTF].include?(entry['category']) }
collection_urls = collection_entries.map { |entry| entry.fetch('url') }
raise 'Collection search destinations must be unique' unless collection_urls.uniq == collection_urls

%w[index.html portfolio/index.html categories/security/index.html].each do |name|
  viewport = read_document.call(root.join(name)).at_css('meta[name="viewport"]')
  raise "Non-responsive viewport: #{name}" unless viewport&.[]('content')&.include?('width=device-width')
end

# Every monolingual post must fall back to its own title and excerpt in KR mode.
monolingual_urls = Dir[source.join('_posts/*.md')].filter_map do |filename|
  header = File.read(filename).split(/^---\s*$\n?/, 3)[1]
  data = YAML.safe_load(header, permitted_classes: [Date, Time], aliases: true)
  next if data['bilingual']
  "/posts/#{File.basename(filename, '.md').sub(/^\d{4}-\d{2}-\d{2}-/, '')}/"
end
root.glob('{index.html,page*/index.html}').each do |file|
  read_document.call(file).css('.post-card, .popular-item').each do |card|
    next unless monolingual_urls.include?(card['href'])
    %w[.post-title .post-excerpt .popular-item-title].each do |selector|
      english = card.at_css("#{selector} [data-lang='en']")
      korean = card.at_css("#{selector} [data-lang='kr']")
      next unless english && korean
      normalize = ->(text) { text.split.join(' ') }
      unless normalize.call(english.text) == normalize.call(korean.text)
        raise "Stale KR content for #{card['href']} in #{file}: #{selector}"
      end
    end
  end
end

category_pages = root.glob('categories/*/index.html')
category_pages.each do |file|
  document = read_document.call(file)
  %w[.cat-hero-title .cat-hero-desc].each do |selector|
    %w[en kr].each do |language|
      content = document.at_css("#{selector} [data-lang='#{language}']")
      raise "Missing #{language} category text: #{file} #{selector}" if content&.text.to_s.strip.empty?
    end
  end
  document.css('.cat-featured-card, .post-card').each do |card|
    title = card.at_css('.cat-featured-title, .post-title')
    excerpt = card.at_css('.cat-featured-excerpt, .post-excerpt')
    %w[en kr].each do |language|
      raise "Missing #{language} category card title: #{file} #{card['href']}" if title.at_css("[data-lang='#{language}']")&.text.to_s.strip.empty?
      raise "Missing #{language} category card excerpt: #{file} #{card['href']}" unless excerpt.at_css("[data-lang='#{language}']")
    end
  end
end

puts "Site regressions passed: #{entries.size} search destinations, viewports, monolingual cards, and #{category_pages.size} bilingual category pages."
