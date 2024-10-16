/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./views/*.{html,js,ejs}"],
  theme: {
    extend: {
      fontFamily: {
        delius: ['"Delius Swash Caps"', "cursive"],
        konit : ["Kanit", "sans-serif"],
        sofadi : ["Sofadi One","system-ui"]
      },
    },
  },
  plugins: [],
}