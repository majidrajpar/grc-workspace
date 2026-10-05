const syncAria = (el) => {
  if (!el.matches || !el.matches("input, textarea, select")) return;
  if (el.matches(":user-invalid")) el.setAttribute("aria-invalid", "true");
  else el.removeAttribute("aria-invalid");
};

document.addEventListener("blur", (event) => syncAria(event.target), true);
document.addEventListener("input", (event) => {
  if (event.target.hasAttribute && event.target.hasAttribute("aria-invalid")) syncAria(event.target);
});

document.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-password-toggle]");
  if (!toggle) return;
  const input = document.getElementById(toggle.dataset.passwordToggle);
  if (!input) return;
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  toggle.textContent = showing ? "Show password" : "Hide password";
});

document.addEventListener("submit", (event) => {
  const button = event.target.querySelector("button[type='submit']");
  if (button) button.disabled = true;
});
