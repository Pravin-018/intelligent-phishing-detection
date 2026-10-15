/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        panel: '#0f172a',
        panelAlt: '#111827',
        accent: '#38bdf8',
        danger: '#f97316',
        warning: '#fbbf24',
        success: '#34d399',
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(56, 189, 248, 0.2), 0 20px 45px rgba(15, 23, 42, 0.6)',
      },
    },
  },
  plugins: [],
}
