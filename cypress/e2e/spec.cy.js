describe('Pruebas del backend en Render', () => {
  it('Debería responder con un estado 200 en la raíz', () => {
    cy.request('https://mi-backend-3prp.onrender.com') // URL del backend en Render
      .its('status')
      .should('equal', 200);
  });
});
