// ***********************************************
// This example commands.js shows you how to
// create various custom commands and overwrite
// existing commands.
//
// For more comprehensive examples of custom
// commands please read more here:
// https://on.cypress.io/custom-commands
// ***********************************************
//
//
// -- This is a parent command --
// Cypress.Commands.add('login', (email, password) => { ... })
//
//
// -- This is a child command --
// Cypress.Commands.add('drag', { prevSubject: 'element'}, (subject, options) => { ... })
//
//
// -- This is a dual command --
// Cypress.Commands.add('dismiss', { prevSubject: 'optional'}, (subject, options) => { ... })
//
//
// -- This will overwrite an existing command --
// Cypress.Commands.overwrite('visit', (originalFn, url, options) => { ... })
const selector = {
  username: "#input",
  password: "#normal_login_password",
  loginButton: ".ant-btn",
};
function getAdminPassword() {
  const password = Cypress.env("adminPassword");
  if (typeof password !== "string" || password.length < 32) {
    throw new Error("CYPRESS_adminPassword must contain the isolated E2E credential");
  }
  return password;
}
Cypress.Commands.add('login', ()=>{
  cy.visit("http://localhost:7001", {
    onBeforeLoad(win) {
      // Disable the page tour so its popover never covers elements the tests click
      win.localStorage.setItem("isTourVisible", "false");
    },
  });
  cy.get(selector.username).type("admin");
  cy.get(selector.password).type(getAdminPassword(), {log: false});
  cy.get(selector.loginButton).click();
  cy.url().should("eq", "http://localhost:7001/");
})
