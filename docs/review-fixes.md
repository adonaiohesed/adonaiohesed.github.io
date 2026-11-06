# Review fixes — 2026-11-06

Scope: the seven confirmed issues from the project review. Existing owner changes
in unrelated posts and the untracked draft/new post must remain untouched.

## Implementation

- Thumbnail updates: restrict changes to front matter; preserve body bytes;
  restore the two FTK Imager definitions from commit `8ed683c^`.
- Scheduled publishing: preflight all filenames before moving, never overwrite,
  use America/Chicago dates, and dispatch Pages deployment after the push.
- Mobile: enable the existing responsive rules through device-width viewports;
  fix overflowing post grids/code, pagination, and portfolio sections. Keep the
  mobile menu scrollable and the mobile TOC available and dismissible.
- Bilingual cards: initialize title/excerpt for each card, including Popular.
- Search: point collection results to stable portfolio anchors; serialize JSON.
- Post generation: quote title, tags, and category safely in both generators.
- Preserve the existing CSS tokens, typography, components, and desktop layouts.
  New search anchors use the existing portfolio sections and floating navigation.

## Validation and delivery

Implemented all seven findings. Local verification completed:

- `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`: 10 passed.
  Covers body/newline preservation, batch preflight, destination collision,
  invalid dates, workflow outputs, and both generators' Ruby YAML round trips.
- Production Jekyll build with disk cache disabled: passed.
- `bundle exec ruby tools/check_site.rb <output>`: 250 search destinations,
  unique collection anchors, viewports, and monolingual card fallbacks passed.
- HTML-Proofer with external requests disabled: 321 files passed, without the
  legacy thumbnail/image exclusions.
- Headless Chrome: home, category, post, and portfolio fit at 320, 390, 768,
  and 1280 CSS pixels. Screenshots were visually inspected. Menu keyboard
  activation, Escape/focus, TOC selection/dismissal, KR fallback, and search to
  the matching portfolio item passed browser assertions.
- Python AST, Bash/Ruby syntax, and `git diff --check`: passed.
- Independent automation and UI reviews completed. The identified TOC overlay
  dismissal issue was fixed and checked in the browser.

Design consistency: existing tokens, components, type, color, and desktop layouts
are retained. Mobile adaptations use wrapping/stacking and existing controls.
Real-device checks, a complete accessibility audit, and external comments or
analytics were not performed.

Delivery target: the existing `main` → GitHub Pages workflow at
<https://adonaiohesed.github.io/>. Deployment evidence is recorded in
[Build and Deploy](https://github.com/adonaiohesed/adonaiohesed.github.io/actions/workflows/pages-deploy.yml)
and the final delivery report. A successful local build alone does not establish
deployment success. Scheduled publication uses fixtures for verification; no
owner draft is published for testing.

Rollback baseline: `de2a0ecdc441adfd3d32fca3c6cee43a14a01924`, previously deployed
by successful run `34333545475`. Revert only the fix commit(s), then run the existing Pages workflow.
Do not include the owner's in-progress content changes in the fix commit(s).
