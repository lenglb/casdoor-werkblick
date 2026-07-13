describe('Test tokens', () => {
  beforeEach(() => {
    cy.login();
  });

  it("prevents manually minting credentials", () => {
    cy.visit("http://localhost:7001/tokens");
    cy.url().should("eq", "http://localhost:7001/tokens");
    cy.get('[data-testid="token-credential-notice"]', {timeout: 10000}).should("be.visible");
    cy.get(".ant-table-title button").should("not.exist");
  });
});
