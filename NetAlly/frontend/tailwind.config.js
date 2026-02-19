/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      fontSize: {
        'ui-xs': ['0.625rem', { lineHeight: '0.875rem' }],
        'ui-sm': ['0.6875rem', { lineHeight: '1rem' }],
        'ui-base': ['0.75rem', { lineHeight: '1.125rem' }],
        'ui-md': ['0.8125rem', { lineHeight: '1.25rem' }],
        'ui-lg': ['0.875rem', { lineHeight: '1.375rem' }],
      },
      colors: {
        border: {
          DEFAULT: "hsl(var(--border))",
          subtle: "hsl(var(--border-subtle, var(--border)))",
          strong: "hsl(var(--border-strong, var(--border)))",
        },
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive, 0 84.2% 60.2%))",
          foreground: "hsl(var(--destructive-foreground, 0 0% 98%))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        popover: {
          DEFAULT: "hsl(var(--popover))",
          foreground: "hsl(var(--popover-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        surface: {
          raised: "hsl(var(--surface-raised, var(--card)))",
          sunken: "hsl(var(--surface-sunken, var(--background)))",
        },
        status: {
          ok: "hsl(var(--status-ok, 152 60% 48%))",
          warn: "hsl(var(--status-warn, 38 90% 55%))",
          error: "hsl(var(--status-error, 0 72% 58%))",
          info: "hsl(var(--status-info, 210 70% 60%))",
        },
      },
      borderRadius: {
        lg: '0.5rem',
        md: 'calc(0.5rem - 2px)',
        sm: 'calc(0.5rem - 4px)',
      },
      boxShadow: {
        'elevation-1': '0 1px 2px 0 rgba(0,0,0,0.3)',
        'elevation-2': '0 2px 6px 0 rgba(0,0,0,0.35), 0 1px 2px 0 rgba(0,0,0,0.2)',
        'elevation-3': '0 4px 16px 0 rgba(0,0,0,0.4), 0 2px 4px 0 rgba(0,0,0,0.25)',
        'elevation-4': '0 8px 30px 0 rgba(0,0,0,0.45), 0 4px 8px 0 rgba(0,0,0,0.3)',
        'glow-primary': '0 0 12px -2px hsl(168 65% 38% / 0.25)',
        'glow-ok': '0 0 10px -2px hsl(152 60% 48% / 0.2)',
        'glow-error': '0 0 10px -2px hsl(0 72% 58% / 0.2)',
      },
    },
  },
  plugins: [],
}
