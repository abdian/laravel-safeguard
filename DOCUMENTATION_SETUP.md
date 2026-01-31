# Documentation Website Setup Guide

This guide will help you set up a beautiful documentation website like Verta for Laravel Safeguard package.

## ✨ What's Included?

A complete documentation website built with VitePress featuring:
- 🏠 Homepage with hero section and features
- 📚 Complete user guide
- 🔒 Security documentation
- 📖 API Reference
- 🎯 Real-world examples
- 🔍 Local search functionality
- 🎨 Beautiful, responsive theme inspired by Laravel docs

## 📋 Prerequisites

1. **Node.js** version 18 or higher
2. **npm** or **yarn**
3. **Git** for deployment

## 🚀 Local Setup

### Step 1: Install Dependencies

```bash
cd C:\www\test-project\#Packages\validator-laravel
npm install
```

### Step 2: Run Development Server

```bash
npm run docs:dev
```

The site will be available at `http://localhost:5173`

### Step 3: Test It Out

1. Open your browser and navigate to `http://localhost:5173`
2. You should see the Laravel Safeguard homepage
3. Test the navigation and sidebar

## 🌐 Deploy to GitHub Pages

### Step 1: GitHub Repository Settings

1. Go to your GitHub repository
2. Navigate to **Settings** → **Pages**
3. Under **Source**:
   - Select: **GitHub Actions**

### Step 2: Configure Base URL

If your repository name is not `laravel-safeguard`, update the `base` in config:

File: `docs/.vitepress/config.js`

```js
export default defineConfig({
  base: '/REPOSITORY-NAME/',  // ⬅️ Change this
  // ...
})
```

### Step 3: Push to GitHub

```bash
git add .
git commit -m "Add VitePress documentation"
git push origin main
```

### Step 4: Wait for Deployment

1. Go to the **Actions** tab in GitHub
2. You should see the "Deploy Documentation" workflow running
3. After completion (about 2-3 minutes), your documentation will be live:

```
https://USERNAME.github.io/REPOSITORY-NAME/
```

Example:
```
https://abdian.github.io/laravel-safeguard/
```

## 📁 File Structure

```
docs/
├── .vitepress/
│   ├── config.js          # ⚙️ Main configuration
│   ├── theme/             # 🎨 Custom theme files
│   │   ├── index.js
│   │   └── custom.css
│   ├── dist/              # 📦 Built files (gitignored)
│   └── cache/             # 💾 Cache (gitignored)
├── guide/                 # 📚 User guide
│   ├── introduction.md
│   ├── getting-started.md
│   └── basic-usage.md
├── api/                   # 📖 API reference
├── security/              # 🔒 Security docs
├── examples/              # 🎯 Examples
├── public/                # 🖼️ Static assets
└── index.md               # 🏠 Homepage
```

## ✏️ Adding New Pages

### Step 1: Create Markdown File

```bash
# Example: Add "Troubleshooting" page
touch docs/guide/troubleshooting.md
```

File content:

```md
# Troubleshooting

## Common Issues

### Issue 1
Description and solution...
```

### Step 2: Add to Sidebar

Edit `docs/.vitepress/config.js`:

```js
sidebar: [
  {
    text: 'Getting Started',
    items: [
      { text: 'Introduction', link: '/guide/introduction' },
      { text: 'Installation', link: '/guide/installation' },
      { text: 'Troubleshooting', link: '/guide/troubleshooting' },  // ⬅️ New
    ]
  },
  // ...
]
```

## 🎨 Customization

### Change Colors

Edit `docs/.vitepress/theme/custom.css`:

```css
:root {
  /* Your custom primary color */
  --vp-c-brand-1: #your-color;
  --vp-c-brand-2: #your-color-lighter;
  --vp-c-brand-3: #your-color-lightest;
}
```

### Change Logo

1. Place your logo in `docs/public/`:
   - `logo.svg` for light mode
   - `logo-dark.svg` for dark mode

2. Logo is already configured in `config.js`:
```js
logo: {
  light: '/logo.svg',
  dark: '/logo-dark.svg'
}
```

### Change Hero Image

Place hero image in `docs/public/hero-image.svg` and update in `index.md`:

```md
hero:
  image:
    src: /hero-image.svg
```

## 📝 Writing Documentation

### Syntax Highlighting

\`\`\`php
$request->validate([
    'file' => 'required|safeguard',
]);
\`\`\`

### Alert Boxes

```md
::: tip Helpful Tip
This is a useful tip for users!
:::

::: warning Important
This is an important warning!
:::

::: danger Dangerous
This operation is dangerous!
:::
```

### Code Groups

\`\`\`md
::: code-group

\`\`\`php [Controller]
public function upload(Request $request) {
    //...
}
\`\`\`

\`\`\`php [Route]
Route::post('/upload', [UploadController::class, 'upload']);
\`\`\`

:::
\`\`\`

## 🔧 Troubleshooting

### Port Already in Use

If port 5173 is already in use:

```bash
npm run docs:dev -- --port 3000
```

### Build Errors

Clear cache:

```bash
rm -rf docs/.vitepress/cache docs/.vitepress/dist
npm run docs:build
```

### 404 on GitHub Pages

Make sure the `base` in config is set correctly.

## 📚 Additional Resources

- [VitePress Documentation](https://vitepress.dev/)
- [Markdown Guide](https://www.markdownguide.org/)
- [GitHub Pages Docs](https://docs.github.com/en/pages)

## 🎉 You're Done!

You now have a professional documentation website! 🚀

For theme customization, see [THEME_GUIDE.md](docs/THEME_GUIDE.md)

If you have questions, create an issue on GitHub.
