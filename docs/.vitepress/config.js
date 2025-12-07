import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'Laravel Safeguard',
  description: 'Secure file upload validation for Laravel',
  base: '/laravel-safeguard/',

  themeConfig: {
    logo: '/logo.svg',

    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API', link: '/api/rules' },
      { text: 'GitHub', link: 'https://github.com/abdian/laravel-safeguard' }
    ],

    sidebar: [
      {
        text: 'Getting Started',
        items: [
          { text: 'Introduction', link: '/guide/introduction' },
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Quick Start', link: '/guide/getting-started' },
        ]
      },
      {
        text: 'Usage',
        items: [
          { text: 'Basic Usage', link: '/guide/basic-usage' },
          { text: 'Validation Rules', link: '/guide/validation-rules' },
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Advanced Usage', link: '/guide/advanced' },
        ]
      },
      {
        text: 'Security',
        items: [
          { text: 'PHP Scanning', link: '/security/php-scanning' },
          { text: 'Image Security', link: '/security/image-security' },
          { text: 'PDF Security', link: '/security/pdf-security' },
          { text: 'SVG Security', link: '/security/svg-security' },
        ]
      },
      {
        text: 'API Reference',
        items: [
          { text: 'Validation Rules', link: '/api/rules' },
          { text: 'Configuration', link: '/api/configuration' },
        ]
      },
      {
        text: 'Examples',
        items: [
          { text: 'Real-world Examples', link: '/examples/real-world' },
          { text: 'Common Scenarios', link: '/examples/common' },
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/abdian/laravel-safeguard' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2025-present Abdian'
    },

    search: {
      provider: 'local'
    }
  }
})
