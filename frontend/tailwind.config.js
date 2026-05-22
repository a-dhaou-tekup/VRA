/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        amber: 'var(--amber)',
        'amber-dim': 'var(--amber-dim)',
        black: 'var(--black)',
        dark: 'var(--dark)',
        surface: 'var(--surface)',
        'surface-2': 'var(--surface-2)',
        border: 'var(--border)',
        text: 'var(--text)',
        muted: 'var(--muted)',
        red: 'var(--red)',
        green: 'var(--green)',
        blue: 'var(--blue)',
        purple: 'var(--purple)',
      },
      fontFamily: {
        syne: ['Syne', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
        inter: ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
