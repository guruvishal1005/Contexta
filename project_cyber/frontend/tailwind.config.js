/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#2563EB',
          dark: '#1F4FD8',
          light: '#3B82F6',
        },
        critical: '#DC2626',
        warning: '#F59E0B',
        success: '#16A34A',
        neutral: '#64748B',
      },
      fontFamily: {
        sans: ['Inter', 'Roboto', 'Open Sans', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
