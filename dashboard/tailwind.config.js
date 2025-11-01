/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#06b6d4',
          dark: '#0e7490',
        },
        critical: '#dc2626',
        high: '#ea580c',
        medium: '#f59e0b',
        low: '#3b82f6',
        info: '#6b7280',
      },
    },
  },
  plugins: [],
}

