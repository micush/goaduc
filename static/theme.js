// Theme: 'auto' (follow OS), 'light' or 'dark'. Loaded in <head> so the
// theme is applied before first paint (CSP forbids inline scripts).
(function () {
  var KEY = 'aduc-theme';
  function get() { try { var v = localStorage.getItem(KEY); if (v === 'light' || v === 'dark') return v; } catch (_) {} return 'auto'; }
  function apply(t) {
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
  }
  window.adTheme = {
    get: get,
    set: function (t) { try { if (t === 'auto') localStorage.removeItem(KEY); else localStorage.setItem(KEY, t); } catch (_) {} apply(t); },
    next: function () { var n = { auto: 'light', light: 'dark', dark: 'auto' }[get()]; this.set(n); return n; },
    label: function () { return { auto: '◐ Auto', light: '☀ Light', dark: '☾ Dark' }[get()]; }
  };
  apply(get());
})();
