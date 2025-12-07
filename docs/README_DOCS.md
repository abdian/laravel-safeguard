# Laravel Safeguard Documentation

This directory contains the documentation website for Laravel Safeguard, built with VitePress.

## Local Development

### Prerequisites

- Node.js 18+ installed
- npm or yarn

### Installation

1. Install dependencies:

```bash
npm install
```

2. Start development server:

```bash
npm run docs:dev
```

The documentation will be available at `http://localhost:5173`

### Building for Production

Build the static site:

```bash
npm run docs:build
```

Preview the production build:

```bash
npm run docs:preview
```

## Deployment to GitHub Pages

The documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch.

### Setup GitHub Pages

1. Go to your repository settings on GitHub
2. Navigate to **Pages** section
3. Under **Source**, select:
   - Source: **GitHub Actions**
4. Push to `main` branch - GitHub Actions will automatically build and deploy

Your documentation will be available at:
```
https://abdian.github.io/laravel-safeguard/
```

## Directory Structure

```
docs/
├── .vitepress/
│   └── config.js          # VitePress configuration
├── guide/                 # User guide pages
│   ├── introduction.md
│   ├── getting-started.md
│   ├── basic-usage.md
│   ├── validation-rules.md
│   ├── configuration.md
│   └── advanced.md
├── api/                   # API reference
│   ├── rules.md
│   └── configuration.md
├── security/              # Security features
│   ├── php-scanning.md
│   ├── image-security.md
│   ├── pdf-security.md
│   └── svg-security.md
├── examples/              # Examples
│   ├── real-world.md
│   └── common.md
├── public/                # Static assets
└── index.md               # Homepage

```

## Writing Documentation

### Adding a New Page

1. Create a new `.md` file in the appropriate directory
2. Add frontmatter if needed:

```md
---
title: Page Title
description: Page description
---

# Page Title

Your content here...
```

3. Update `.vitepress/config.js` sidebar to include the new page

### Using Components

VitePress supports Vue components in markdown:

```md
::: tip
This is a tip box
:::

::: warning
This is a warning box
:::

::: danger
This is a danger box
:::
```

### Code Blocks

```md
\`\`\`php
// Your PHP code here
$request->validate([
    'file' => 'required|safeguard',
]);
\`\`\`
```

## Customization

### Theme

Edit `.vitepress/config.js` to customize:
- Navigation
- Sidebar
- Colors
- Logo
- Social links

### Assets

Place images and assets in `docs/public/` directory.

## Need Help?

- [VitePress Documentation](https://vitepress.dev/)
- [Laravel Safeguard Repository](https://github.com/abdian/laravel-safeguard)
