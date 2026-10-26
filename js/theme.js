// Applies a saved light/dark choice before first paint (CSP forbids inline scripts).
try {
  var t = localStorage.getItem("theme");
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
} catch (e) { /* storage blocked: follow the system setting */ }
