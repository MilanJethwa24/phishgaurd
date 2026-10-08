// Front-end helpers: tab switching and client-side validation. Never opens any URL.
document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("scan-form");
  if (!form) return;
  const typeInput = document.getElementById("input_type");
  const emailField = document.getElementById("email-field");
  const urlField = document.getElementById("url-field");
  const emailInput = document.getElementById("email-input");
  const urlInput = document.getElementById("url-input");
  const counter = document.getElementById("char-count");
  const errorBox = document.getElementById("form-error");

  document.querySelectorAll(".tab").forEach(function (tab) {
    tab.addEventListener("click", function () {
      document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      const isUrl = tab.dataset.type === "url";
      typeInput.value = tab.dataset.type;
      emailField.classList.toggle("hidden", isUrl);
      urlField.classList.toggle("hidden", !isUrl);
      // Only the visible field is submitted as input_text
      emailInput.disabled = isUrl; emailInput.name = isUrl ? "" : "input_text";
      urlInput.disabled = !isUrl; urlInput.name = isUrl ? "input_text" : "";
      errorBox.textContent = "";
    });
  });

  emailInput.addEventListener("input", () => { counter.textContent = emailInput.value.length; });

  form.addEventListener("submit", function (e) {
    const isUrl = typeInput.value === "url";
    const value = (isUrl ? urlInput.value : emailInput.value).trim();
    if (!value) { e.preventDefault(); errorBox.textContent = "Please enter something to scan."; return; }
    if (isUrl && /\s/.test(value)) { e.preventDefault(); errorBox.textContent = "A URL cannot contain spaces."; return; }
    form.querySelector("button[type=submit]").textContent = "Scanning...";
  });
});
