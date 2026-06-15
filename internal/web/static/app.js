// Edge Guardian dashboard — minimal progressive enhancement. No framework, CSP-clean
// (served from /static, never inline). Sole job: persist the light/dark theme choice
// and wire the toggle button. HTMX handles everything else declaratively.
(function () {
  "use strict";

  var STORE_KEY = "nsg-theme";
  var root = document.documentElement;

  function apply(theme) {
    if (theme === "dark" || theme === "light") {
      root.setAttribute("data-theme", theme);
    }
  }

  // Restore saved choice; otherwise follow the OS preference.
  try {
    var saved = window.localStorage.getItem(STORE_KEY);
    if (saved) {
      apply(saved);
    } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      apply("dark");
    }
  } catch (e) {
    /* localStorage may be blocked; theme just stays at the default. */
  }

  function toggle() {
    var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
    apply(next);
    try {
      window.localStorage.setItem(STORE_KEY, next);
    } catch (e) {
      /* ignore persistence failure */
    }
  }

  // Mobile nav: the hamburger toggles the primary nav dropdown. On desktop the nav is
  // always visible and the button is hidden, so this is a no-op there.
  function toggleNav(btn) {
    var nav = document.getElementById("primary-nav");
    if (!nav) return;
    var open = nav.classList.toggle("is-open");
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  }

  document.addEventListener("click", function (ev) {
    var closest = ev.target.closest ? ev.target.closest.bind(ev.target) : null;
    if (!closest) return;

    var themeBtn = closest("[data-theme-toggle]");
    if (themeBtn) {
      ev.preventDefault();
      toggle();
      return;
    }

    var navBtn = closest("[data-nav-toggle]");
    if (navBtn) {
      ev.preventDefault();
      toggleNav(navBtn);
      return;
    }

    // A tap on a nav link closes the open dropdown so the next page isn't left with a
    // stale-open menu.
    if (closest(".nav__link")) {
      var nav = document.getElementById("primary-nav");
      var hb = document.querySelector("[data-nav-toggle]");
      if (nav) nav.classList.remove("is-open");
      if (hb) hb.setAttribute("aria-expanded", "false");
    }
  });

  // Pause the full /feed live poll while the reader is scrolled down, so an auto-refresh
  // never yanks away the rows they're reading. Polling resumes automatically once they
  // scroll back to the top. Other pollers (sentinel, readouts, overview recent) are
  // unaffected. A small "paused" hint is toggled if present.
  document.body.addEventListener("htmx:beforeRequest", function (ev) {
    var elt = ev.detail && ev.detail.elt;
    if (elt && elt.id === "live-feed" && window.scrollY > 8) {
      ev.preventDefault();
      var hint = document.getElementById("feed-live-hint");
      if (hint) hint.setAttribute("data-paused", "true");
    } else if (elt && elt.id === "live-feed") {
      var h = document.getElementById("feed-live-hint");
      if (h) h.removeAttribute("data-paused");
    }
  });
})();
