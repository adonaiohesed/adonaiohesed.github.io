# Blog editing conventions

Read `docs/editorial-style.md` before writing or editing Korean blog prose.
Use Korean 한다체 for technical articles, guides, and personal writing. Preserve
the author's experience, values, uncertainty, tense, negation, and recommendation
strength. Quotes, interview answers, emails, prompts, code/comments, and English
prose retain their original content and register.

For tone-only edits, preserve front matter, public/draft status, filenames,
headings/anchors, section order, bilingual separators, Markdown structure,
URLs/images, code/math, and numerical facts. Keep existing owner changes.
Make a pre-edit snapshot and run `tools/check_editorial_preservation.rb` before
claiming preservation. Review the changed sentences as well as automated checks.

Site checks: `python3 -m unittest discover -s tests -v`, production Jekyll build,
`bundle exec ruby tools/check_site.rb _site`, and HTML-Proofer internal checks.
Deploy only through the existing GitHub Pages workflow after validation.
