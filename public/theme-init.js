// Theme flash prevention: apply cached theme before first paint.
// The authoritative value comes from preferences.json via IPC later;
// localStorage is just a fast synchronous cache to prevent FOUC.
(function() {
  try {
    var t = localStorage.getItem("verrou-theme");
    if (t === "light" || t === "dark") {
      document.documentElement.dataset.theme = t;
    }
    // "system" or missing → no data-theme → CSS media query decides
  } catch(e) { /* localStorage unavailable */ }
})();
