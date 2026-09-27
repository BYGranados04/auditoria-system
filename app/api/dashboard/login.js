"use strict";

const form = document.querySelector("#login-form");
const button = document.querySelector("#login-button");
const errorMessage = document.querySelector("#login-error");

document.querySelectorAll("[data-password-toggle]").forEach((toggle) => {
  const input = document.querySelector(`#${toggle.getAttribute("aria-controls")}`);
  toggle.addEventListener("click", () => {
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    toggle.setAttribute("aria-pressed", String(visible));
    toggle.setAttribute(
      "aria-label",
      visible ? "Ocultar contraseña" : "Mostrar contraseña",
    );
    toggle.querySelector(".password-icon-show").hidden = visible;
    toggle.querySelector(".password-icon-hide").hidden = !visible;
  });
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  errorMessage.hidden = true;
  const data = new FormData(form);
  try {
    const response = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({
        username: data.get("username"),
        password: data.get("password"),
      }),
    });
    if (!response.ok) {
      errorMessage.textContent = response.status === 401
        ? "Usuario o contraseña incorrectos."
        : "No fue posible iniciar sesión.";
      errorMessage.hidden = false;
      return;
    }
    window.location.assign("/dashboard");
  } catch {
    errorMessage.textContent = "No fue posible conectar con la API local.";
    errorMessage.hidden = false;
  } finally {
    button.disabled = false;
  }
});
