describe("Pruebas del backend en localhost", () => {
  it("Debería responder con un estado 200 en /api/inicio", () => {
    cy.request("/api/inicio")
      .its("status")
      .should("equal", 200);
  });
});
