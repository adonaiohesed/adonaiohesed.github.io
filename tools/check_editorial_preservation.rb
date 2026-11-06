#!/usr/bin/env ruby
# Compare content-sensitive fingerprints before/after a Korean tone edit.
require 'json'
require 'digest'
require 'kramdown'
require 'kramdown-parser-gfm'

module EditorialPreservation
  module_function

  def digest(value)
    Digest::SHA256.hexdigest(JSON.generate(value))
  end

  def text_of(node)
    node.value.to_s + node.children.map { |child| text_of(child) }.join
  end

  def tree(node, protected)
    if %i[codeblock codespan math raw xml_comment].include?(node.type)
      protected << [node.type, node.value, node.attr]
    elsif node.type == :header
      protected << [:header, node.options[:level], text_of(node), node.attr]
    elsif %i[img a].include?(node.type)
      protected << [node.type, node.attr, text_of(node)]
    end
    # Attribute changes can alter URLs, HTML behavior, IDs, or image captions.
    [node.type, node.attr, node.options[:level], node.children.map { |child| tree(child, protected) }]
  end

  def fingerprint(source)
    front = source.match(/\A---[^\S\n]*\r?\n(.*?)^---[^\S\n]*\r?\n?/m)
    raise 'Missing front matter' unless front

    body = source[front.end(0)..]
    document = Kramdown::Document.new(body, input: 'GFM')
    protected = []
    structure = tree(document.root, protected)
    {
      'front_matter' => digest(front[0]),
      'protected_nodes' => digest(protected),
      'structure' => digest(structure),
      'english_and_numbers' => digest(body.scan(/[A-Za-z]+|\d+(?:\.\d+)*/)),
      'non_korean_lines' => digest(body.lines.reject { |line| line.match?(/[가-힣]/) }),
      'indentation' => digest(body.lines.map { |line| line[/\A[ \t]*/] }),
      'line_endings' => digest(body.lines.map { |line| line.end_with?("\r\n") ? 'CRLF' : line.end_with?("\n") ? 'LF' : 'EOF' }),
      'horizontal_rules' => digest(body.lines.select { |line| line.match?(/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/) }),
      'quoted_examples' => digest(body.scan(/"[^"\n]*"|“[^”\n]*”|‘[^’\n]*’|'[^'\n]*'/))
    }
  end

  def snapshot(directory)
    Dir[File.join(directory, '*.md')].sort.to_h do |filename|
      [File.basename(filename), fingerprint(File.read(filename))]
    end
  end

  def compare(before, after)
    failures = []
    failures << 'Post filenames changed' unless before.keys.sort == after.keys.sort
    (before.keys & after.keys).each do |filename|
      before[filename].each do |field, expected|
        failures << "#{filename}: #{field} changed" unless after[filename][field] == expected
      end
    end
    failures
  end
end

if $PROGRAM_NAME == __FILE__
  command, baseline, directory = ARGV
  abort 'Usage: check_editorial_preservation.rb snapshot|check BASELINE.json POSTS_DIRECTORY' unless %w[snapshot check].include?(command) && baseline && directory
  current = EditorialPreservation.snapshot(directory)
  if command == 'snapshot'
    File.write(baseline, JSON.pretty_generate(current) + "\n")
    puts "Recorded preservation fingerprints for #{current.size} posts."
  else
    failures = EditorialPreservation.compare(JSON.parse(File.read(baseline)), current)
    abort failures.join("\n") unless failures.empty?
    puts "Editorial preservation passed for #{current.size} posts: metadata, code/math, headings, URLs/attributes, English/numbers, structure, and line boundaries."
  end
end
