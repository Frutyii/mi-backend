const { defineConfig } = require("cypress");

module.exports = defineConfig({
  e2e: {
    setupNodeEvents(on, config) {
      // Eventos personalizados, si es necesario
    },
    baseUrl: "http://localhost:3000", // URL base para las pruebas
  },
});


