// public/app.js  (STARTER / VULNERABLE build)
//
// Client-side code for the listing page. It supports a "shared note" feature:
// a note can be appended to the URL, e.g.  /listing/1#note=hello  and the page
// shows it in a banner.
//
// The value is read straight out of location.hash and injected with
// .innerHTML, so it is parsed as HTML. This is a DOM-based XSS (defect FIX 4):
// the payload never touches the server, yet it still executes in the browser.
//
// Fix idea: render the note as TEXT, not HTML (assign to .textContent, or
// build a text node), so markup in the URL is displayed literally.

(function () {
  const bannerEl = document.getElementById('share-banner');
  if (!bannerEl) return;

  if (location.hash.startsWith('#note=')) {
    const note = decodeURIComponent(location.hash.replace(/^#note=/, ''));

    // ---- FIX 4 (client, DOM-based XSS) ----------------------------------
    const banner = document.createElement('div');
banner.className = 'banner';
banner.textContent = `📎 Shared note: ${note}`;
bannerEl.replaceChildren(banner);
  }
})();
