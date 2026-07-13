describe("Login test", () => {
  const invalidPassword = "Werkblick-E2E-fixed-invalid-password";
  const selector = {
    username: "#input",
    password: "#normal_login_password",
    loginButton: ".ant-btn",
  };
  const getAdminPassword = () => {
    const password = Cypress.env("adminPassword");
    if (typeof password !== "string" || password.length < 32) {
      throw new Error("CYPRESS_adminPassword must contain the isolated E2E credential");
    }
    return password;
  };
  it("Login succeeded", () => {
    cy.request({
      log: false,
      method: "POST",
      url: "http://localhost:7001/api/login",
      body: {
        "application": "app-built-in",
        "organization": "built-in",
        "username": "admin",
        "password": getAdminPassword(),
        "autoSignin": true,
        "type": "login",
      },
    }).then((Response) => {
      expect(Response).property("body").property("status").to.equal("ok");
    });
  });
  it("ui Login succeeded", () => {
    cy.visit("http://localhost:7001");
    cy.get(selector.username).type("admin");
    cy.get(selector.password).type(getAdminPassword(), {log: false});
    cy.get(selector.loginButton).click();
    cy.url().should("eq", "http://localhost:7001/");
  });

  it("Login failed", () => {
    cy.request({
      log: false,
      method: "POST",
      url: "http://localhost:7001/api/login",
      body: {
        "application": "app-built-in",
        "organization": "built-in",
        "username": "admin",
        "password": invalidPassword,
        "autoSignin": true,
        "type": "login",
      },
    }).then((Response) => {
      expect(Response).property("body").property("status").to.equal("error");
    });
  });
  it("ui Login failed", () => {
    cy.visit("http://localhost:7001");
    cy.get(selector.username).type("admin");
    cy.get(selector.password).type(invalidPassword, {log: false});
    cy.get(selector.loginButton).click();
    cy.url().should("eq", "http://localhost:7001/login");
  });
});
