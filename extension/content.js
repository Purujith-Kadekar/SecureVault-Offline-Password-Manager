/**
 * content.js — DOM autofill + credential overlay plumbing.
 *
 * Loaded AFTER urlMatcher.js (which provides domain utilities via a
 * Symbol-keyed namespace — E8 fix: no window.getBaseDomain global).
 *
 * IMPORTANT (Bitwarden-style refactor):
 *   This file NO LONGER injects a lock icon on password inputs. The
 *   previous version wrapped each <input type="password"> in a <div>,
 *   which broke site CSS layouts that relied on the input being a direct
 *   child of its parent (flex :last-child, grid, sibling combinators).
 *   It also duplicated the icon that inline-overlay.js injects, leading
 *   to overlapping interactive elements (bugs B5 + B6).
 *
 *   inline-overlay.js is now the SOLE owner of the field button. It uses
 *   a floating position:fixed custom element (Bitwarden's pattern), which
 *   never re-parents the input. This file only handles the
 *   `trigger_autofill` message from the context menu.
 *
 * E8: No window globals. Injection guard uses a private Symbol on the
 * document (not exposed to page scripts). Domain utilities accessed via
 * Symbol-keyed namespace shared by urlMatcher.js.
 *
 * Autofill uses direct DOM injection — the OS clipboard is NEVER involved.
 */

(function () {
  'use strict';

  // ─── E8: Private injection guard (Symbol on document, not window) ─────
  // Previously: window.__svContentInjected (string key, detectable by page
  // scripts). Now: a Symbol key that page scripts cannot discover through
  // Object.keys() enumeration. The Symbol is unique per extension context
  // and is NOT shared with page scripts.
  const _svContentInjected = Symbol.for('SecureVault.contentInjected');
  if (document[_svContentInjected]) return;
  document[_svContentInjected] = true;

  // ─── E8: Access domain utilities via Symbol (no window.getBaseDomain) ──
  // urlMatcher.js stores { getBaseDomain, domainMatches } under
  // Symbol.for('SecureVault.domainUtils') on window. Access it here.
  // If urlMatcher.js hasn't loaded (rare), fall back to async message
  // to background.js — but for most synchronous uses, the Symbol access
  // works since urlMatcher.js loads first (manifest.json order).
  const _svUtils = Symbol.for('SecureVault.domainUtils');
  const _domainUtils = window[_svUtils];

  // No-op: inline-overlay.js now owns all field-button injection and the
  // credential list popover. We deliberately do NOT scan for password
  // inputs here anymore — that was the source of the layout-breaking
  // wrap-in-div behavior.

  // ─── Programmatic autofill via native value setter ───────────────────
  // Used by the context-menu "Auto-fill login" action (which is handled
  // entirely by inline-overlay.js now). Kept here for backwards compat
  // with any future content scripts that may need it.

  function setNativeValue(el, value) {
    const proto =
      el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype :
      el.tagName === 'SELECT'   ? HTMLSelectElement.prototype   :
                                  HTMLInputElement.prototype;
    const desc = Object.getOwnPropertyDescriptor(proto, 'value');
    if (desc && desc.set) {
      desc.set.call(el, value);
    } else {
      el.value = value;
    }
  }
})();
