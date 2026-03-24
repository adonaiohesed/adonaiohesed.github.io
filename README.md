# Hyoeun's Wiki - hyoeun-blog-theme

A custom Jekyll blog theme built from scratch for Hyoeun's personal knowledge repository and portfolio.

## 📚 About

This is a personal blog showcasing knowledge in cybersecurity, ethical hacking, software engineering, AI/ML, and career development. The site features a clean, modern design with support for multiple languages (English/Korean).

## ✨ Features

- **Responsive Design**: Optimized for desktop, tablet, and mobile devices
- **Bilingual Support**: English/Korean language toggle
- **Dark/Light Theme**: Automatic theme detection with manual override
- **Table of Contents**: Auto-generated TOC for easy navigation in posts
- **Category & Tag System**: Organized content discovery
- **Related Posts**: Suggestions for related articles
- **SEO Optimized**: Built-in SEO meta tags and sitemap
- **PWA Support**: Installable progressive web app
- **Fast Performance**: Minified CSS and optimized assets

## 🛠️ Tech Stack

- **Static Site Generator**: Jekyll 4.3+
- **Theme**: hyoeun-blog-theme (custom)
- **Styling**: SCSS
- **Comments**: Giscus
- **Analytics**: Google Analytics + GoatCounter
- **Deployment**: GitHub Pages

## 📝 Post Structure

Posts can include both English and Korean versions in a single file. Use the language toggle to switch between versions.

### Front Matter Example

```yaml
---
title: Post Title
tags: tag1 tag2
key: page-unique-key
categories:
  - Category
  - Subcategory
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/image.png"
---
```

## 🚀 Getting Started

### Prerequisites

- Ruby 3.0+
- Bundler

### Installation

```bash
# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve --livereload

# Build for production
bundle exec jekyll build
```

## 📂 Project Structure

```
.
├── _posts/          # Blog posts
├── _tabs/           # About, Projects, CTF pages
├── _layouts/        # Page templates
├── _includes/       # Reusable components
├── _sass/           # Stylesheets
├── assets/          # Images, JS, CSS
├── _config.yml      # Jekyll configuration
└── Gemfile          # Ruby dependencies
```

## 🎨 Customization

### Colors & Fonts

Edit `_sass/` directory to customize the theme colors and typography.

### Navigation

Update the navigation links in `_layouts/default.html`.

## 📄 License

MIT License - See LICENSE file for details.

## 👤 Author

**Hyoeun Choi**
- GitHub: [@adonaiohesed](https://github.com/adonaiohesed)
- Email: hyoeun.choi@outlook.com
- LinkedIn: [hyoeun-choi](https://linkedin.com/in/hyoeun-choi)
