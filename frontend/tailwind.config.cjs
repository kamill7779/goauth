/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Geist', 'Satoshi', 'Source Han Sans SC', 'PingFang SC', 'Microsoft YaHei', 'sans-serif'],
      },
      colors: {
        canvas: {
          DEFAULT: 'var(--bg)',
          subtle: 'var(--bg-subtle)',
        },
        surface: {
          DEFAULT: 'var(--surface)',
          solid: 'var(--surface-solid)',
          hover: 'var(--surface-hover)',
          muted: 'var(--surface-muted)',
          sunken: 'var(--surface-sunken)',
        },
        ink: {
          DEFAULT: 'var(--ink)',
          secondary: 'var(--ink-secondary)',
          tertiary: 'var(--ink-tertiary)',
          muted: 'var(--ink-muted)',
          inverse: 'var(--ink-inverse)',
        },
        line: {
          DEFAULT: 'var(--border)',
          strong: 'var(--border-strong)',
          focus: 'var(--border-focus)',
        },
        brand: {
          DEFAULT: 'var(--accent)',
          hover: 'var(--accent-hover)',
          soft: 'var(--accent-soft)',
        },
        danger: {
          DEFAULT: 'var(--error)',
          soft: 'var(--error-soft)',
          strong: 'var(--error-strong)',
        },
        warn: {
          DEFAULT: 'var(--warning)',
          soft: 'var(--warning-soft)',
          strong: 'var(--warning-strong)',
        },
        ok: {
          DEFAULT: 'var(--success)',
          soft: 'var(--success-soft)',
          strong: 'var(--success-strong)',
        },
        info: {
          DEFAULT: 'var(--info)',
          soft: 'var(--info-soft)',
        },
      },
      boxShadow: {
        'soft-sm': 'var(--shadow-sm)',
        'soft-md': 'var(--shadow-md)',
        'soft-lg': 'var(--shadow-lg)',
      },
    },
  },
  plugins: [],
};
