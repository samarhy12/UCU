/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/js/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          900: "#0A1220",
          800: "#111B2E",
          700: "#182338",
          600: "#28374F",
        },
        gold: {
          100: "#E9DFC4",
          300: "#E2BC66",
          400: "#9C7A34",
          500: "#8A6B2E",
        },
        cream: {
          100: "#F6F4EF",
          200: "#EFEBE0",
        },
        ink: {
          900: "#161E2C",
          600: "#4B5364",
          400: "#818A99",
        },
        line: "#DEDACC",
        ucu: { red: "#C8202F", gold: "#F2B51C", green: "#0E8F4D" },
      },
      fontFamily: {
        display: ["Fraunces", "Georgia", "serif"],
        body: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["IBM Plex Mono", "SFMono-Regular", "Menlo", "monospace"],
      },
      keyframes: {
        fadeUp: { "0%": { opacity: "0", transform: "translate3d(0,20px,0)" }, "100%": { opacity: "1", transform: "none" } },
        drift: { "0%,100%": { transform: "translate3d(0,0,0) scale(1)" }, "50%": { transform: "translate3d(24px,-30px,0) scale(1.08)" } },
        shine: { "0%": { backgroundPosition: "0% 50%" }, "100%": { backgroundPosition: "200% 50%" } },
      },
      boxShadow: {
        card: "0 1px 2px rgba(10,18,32,0.05)",
        pop: "0 4px 16px -4px rgba(10,18,32,0.25)",
      },
      borderRadius: {
        xl2: "6px",
      },
    },
  },
  plugins: [],
};
