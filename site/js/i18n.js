/* Client-side internationalization for the Leakwatch site.
   - Detects language from localStorage, then the browser, then falls back to EN.
   - Applies UI strings to [data-i18n], [data-i18n-html], [data-i18n-attr] nodes.
   - Persists the choice and broadcasts `lw:langchange` so the docs portal can
     re-render the active page in the new language. */
(function () {
  "use strict";

  var STORAGE_KEY = "leakwatch-lang";
  var SUPPORTED = ["en", "tr"];
  var DEFAULT = "en";
  var T = window.LW_T || {};

  function detect() {
    var saved = localStorage.getItem(STORAGE_KEY);
    if (saved && SUPPORTED.indexOf(saved) !== -1) return saved;
    var nav = (navigator.language || navigator.userLanguage || DEFAULT).slice(0, 2).toLowerCase();
    return SUPPORTED.indexOf(nav) !== -1 ? nav : DEFAULT;
  }

  var current = detect();

  function t(key, lang) {
    lang = lang || current;
    var dict = T[lang] || {};
    if (key in dict) return dict[key];
    if (T[DEFAULT] && key in T[DEFAULT]) return T[DEFAULT][key];
    return null;
  }

  function apply(lang) {
    document.documentElement.setAttribute("lang", lang);

    document.querySelectorAll("[data-i18n]").forEach(function (el) {
      var v = t(el.getAttribute("data-i18n"), lang);
      if (v !== null) el.textContent = v;
    });
    document.querySelectorAll("[data-i18n-html]").forEach(function (el) {
      var v = t(el.getAttribute("data-i18n-html"), lang);
      if (v !== null) el.innerHTML = v;
    });
    document.querySelectorAll("[data-i18n-attr]").forEach(function (el) {
      el.getAttribute("data-i18n-attr").split(",").forEach(function (pair) {
        var bits = pair.split(":");
        if (bits.length === 2) {
          var v = t(bits[1].trim(), lang);
          if (v !== null) el.setAttribute(bits[0].trim(), v);
        }
      });
    });

    // Reflect state in the language switcher.
    var label = document.getElementById("langCurrent");
    if (label) label.textContent = lang.toUpperCase();
    document.querySelectorAll("#langMenu [data-lang]").forEach(function (b) {
      b.setAttribute("aria-current", b.getAttribute("data-lang") === lang ? "true" : "false");
    });
  }

  function setLang(lang) {
    if (SUPPORTED.indexOf(lang) === -1 || lang === current) {
      if (lang === current) closeMenu();
      return;
    }
    current = lang;
    localStorage.setItem(STORAGE_KEY, lang);
    apply(lang);
    closeMenu();
    document.dispatchEvent(new CustomEvent("lw:langchange", { detail: { lang: lang } }));
  }

  function closeMenu() {
    var menu = document.getElementById("langMenu");
    var toggle = document.getElementById("langToggle");
    if (menu) menu.classList.remove("open");
    if (toggle) toggle.setAttribute("aria-expanded", "false");
  }

  function wireSwitcher() {
    var toggle = document.getElementById("langToggle");
    var menu = document.getElementById("langMenu");
    if (!toggle || !menu) return;

    toggle.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = menu.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    menu.querySelectorAll("[data-lang]").forEach(function (btn) {
      btn.addEventListener("click", function () { setLang(btn.getAttribute("data-lang")); });
    });
    document.addEventListener("click", function (e) {
      if (!menu.contains(e.target) && e.target !== toggle) closeMenu();
    });
    document.addEventListener("keydown", function (e) { if (e.key === "Escape") closeMenu(); });
  }

  // Public API for other scripts (docs.js).
  window.LWI18n = {
    getLang: function () { return current; },
    setLang: setLang,
    t: t,
    supported: SUPPORTED
  };

  function init() {
    apply(current);
    wireSwitcher();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
