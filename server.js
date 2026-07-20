// server.js  —  GreenThumb (STARTER / VULNERABLE build)
// CYSE 411 · Assignment 3
//
// This file ships with intentional security defects, tagged FIX 1 .. FIX 5 in
// the comments below. Each tag matches a task in README.md. Your job is to
// close every one of them WITHOUT breaking the feature it belongs to.
// Search this file for "FIX 1", "FIX 2", ... to find each defect.

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { initDb, all, get, run } = require('./lib/db');

const app = express();
const PORT = process.env.PORT || 3000;

// FIX 5B: Apply a restrictive Content Security Policy to every response.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "object-src 'none'",
      "base-uri 'none'",
      "frame-ancestors 'none'",
    ].join('; ')
  );

  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// Tiny in-memory session store:  token -> username
// ---------------------------------------------------------------------------
const sessions = new Map();

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  raw.split(';').forEach((pair) => {
    const i = pair.indexOf('=');
    if (i > -1) out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  });
  return out;
}

function currentUser(req) {
  const sid = parseCookies(req).sid;
  return sid && sessions.has(sid) ? sessions.get(sid) : null;
}
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ---------------------------------------------------------------------------
// HTML layout helper. All pages share this shell.
// ---------------------------------------------------------------------------
function layout(title, body, req) {
  const user = currentUser(req);
  const nav = user
    ? `<a href="/me">${user}</a> · <a href="/logout">log out</a>`
    : `<a href="/login">log in</a>`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title} · GreenThumb</title>
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">🌱 GreenThumb</a>
    <form class="search" action="/search" method="get">
      <input name="q" placeholder="Search listings…" aria-label="Search listings">
    </form>
    <nav>${nav}</nav>
  </header>
  <main>${body}</main>
  <footer>GreenThumb · a CYSE 411 teaching app · not for production use</footer>
  <script src="/app.js"></script>
</body>
</html>`;
}

// ===========================================================================
// Home
// ===========================================================================
app.get('/', (req, res) => {
  const listings = all(
    `SELECT id, title, species, location FROM listings ORDER BY created_at DESC`
  );
  const cards = listings
    .map(
      (l) => `<article class="card">
        <h2><a href="/listing/${l.id}">${l.title}</a></h2>
        <p class="species">${l.species}</p>
        <p class="meta">📍 ${l.location}</p>
      </article>`
    )
    .join('');
  res.send(layout('Home', `<h1>Recent swaps</h1><div class="grid">${cards}</div>`, req));
});

// ===========================================================================
// Search
// ===========================================================================
app.get('/search', (req, res) => {
  const q = typeof req.query.q === 'string' ? req.query.q : '';

  const requestedSort =
    typeof req.query.sort === 'string'
      ? req.query.sort
      : 'created_at DESC';

  const allowedSorts = {
    'created_at DESC': 'created_at DESC',
    species: 'species ASC',
    title: 'title ASC',
    'title DESC': 'title DESC',
  };

  const sort = allowedSorts[requestedSort] || 'created_at DESC';

  const sql =
    `SELECT id, title, species, location FROM listings ` +
    `WHERE title LIKE ? OR species LIKE ? ` +
    `ORDER BY ${sort}`;

  const searchValue = `%${q}%`;

  let rows = [];
  let error = null;

  try {
    rows = all(sql, [searchValue, searchValue]);
  } catch (e) {
    error = e.message;
  }

  const results = rows
    .map(
      (r) => `<article class="card">
        <h2><a href="/listing/${r.id}">${r.title}</a></h2>
        <p class="species">${r.species}</p>
        <p class="meta">📍 ${r.location}</p>
      </article>`
    )
    .join('');

  // ---- FIX 3: REFLECTED XSS ---------------------------------------------
  // The raw search term is echoed back into the HTML response, so whatever
  // the visitor typed is parsed by the browser as markup.
  // Fix idea: HTML-encode any untrusted value before it lands in the page.
  const safeQ = escapeHtml(q);
  const heading = `<h1>Search</h1><p class="note">Showing results for “${safeQ}”</p>`;

  const bodyErr = error ? `<p class="error">Query error: ${error}</p>` : '';
  const list = rows.length ? `<div class="grid">${results}</div>` : '<p>No matches.</p>';
  res.send(layout('Search', heading + bodyErr + list, req));
});

// ===========================================================================
// Login / logout
// ===========================================================================
app.get('/login', (req, res) => {
  const failed = req.query.failed ? '<p class="error">Invalid credentials.</p>' : '';
  res.send(
    layout(
      'Log in',
      `<h1>Log in</h1>${failed}
       <form class="stack" action="/login" method="post">
         <label>Username <input name="username" autocomplete="username"></label>
         <label>Password <input name="password" type="password" autocomplete="current-password"></label>
         <button type="submit">Log in</button>
       </form>`,
      req
    )
  );
});

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // ---- FIX 1: SQL INJECTION (authentication bypass) ---------------------
  // Credentials are concatenated into the query, so an attacker who injects
  // SQL can make the WHERE clause true without knowing any password
  // (e.g. a username of  curator' --  comments the password check away).
  // Fix idea: use a parameterized query so inputs are treated as pure data.
  const sql =
  `SELECT id, username FROM users ` +
  `WHERE username = ? AND password = ?`;

let user = null;
try {
  user = get(sql, [username, password]);
} catch (e) {
  // Fall through to login failure.
}

  if (!user) return res.redirect('/login?failed=1');

  const token = crypto.randomBytes(16).toString('hex');
  sessions.set(token, user.username);

  // ---- FIX 5 (part A): INSECURE SESSION COOKIE --------------------------
  // The session cookie is set with no protective attributes, so any script
  // on the page can read it via document.cookie and the browser attaches it
  // to cross-site requests.
  // Fix idea: add HttpOnly and SameSite (and Secure when served over HTTPS).
  const secureFlag = req.secure ? '; Secure' : '';

res.setHeader(
  'Set-Cookie',
  `sid=${token}; Path=/; HttpOnly; SameSite=Strict${secureFlag}`
);
  res.redirect('/me');
});

app.get('/logout', (req, res) => {
  const sid = parseCookies(req).sid;

  if (sid) {
    sessions.delete(sid);
  }

  const secureFlag = req.secure ? '; Secure' : '';

  res.setHeader(
    'Set-Cookie',
    `sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict${secureFlag}`
  );

  res.redirect('/');
});

// ===========================================================================
// Profile (requires a session — proves what a stolen cookie is worth)
// ===========================================================================
app.get('/me', (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  const mine = all(
    `SELECT id, title, species FROM listings WHERE user_id = (SELECT id FROM users WHERE username = ?) ORDER BY created_at DESC`,
    [user]
  );
  const list = mine.length
    ? mine.map((l) => `<li><a href="/listing/${l.id}">${l.title}</a> — ${l.species}</li>`).join('')
    : '<li>You have no listings yet.</li>';
  res.send(
    layout('Profile', `<h1>Hello, ${user}</h1><p>Your listings:</p><ul>${list}</ul>`, req)
  );
});

// ===========================================================================
// Listing detail (comments are rendered server-side)
// ===========================================================================
app.get('/listing/:id', (req, res) => {
  const l = get(`SELECT * FROM listings WHERE id = ?`, [Number(req.params.id)]);
  if (!l) return res.status(404).send(layout('Not found', '<h1>Listing not found</h1>', req));

  const comments = all(
    `SELECT author, body, created_at FROM comments WHERE listing_id = ? ORDER BY created_at ASC`,
    [l.id]
  );

  // ---- FIX 4: STORED XSS ------------------------------------------------
  // Each comment body was stored exactly as received (see POST handler
  // below) and is now concatenated into the page without encoding, so a
  // comment can carry markup that the browser executes for every visitor.
  // Fix idea: HTML-encode the stored body on output (and/or sanitize on
  //   input). Do the same wherever else user text is printed.
  const commentsHtml = comments.length
  ? comments
      .map(
        (c) => `<div class="comment">
           <p class="comment-body">${escapeHtml(c.body)}</p>
           <p class="comment-meta">— ${escapeHtml(c.author)}, ${escapeHtml(c.created_at)}</p>
         </div>`
      )
      .join('')
  : '<p>No comments yet. Be the first!</p>';

  // Description comes from a trusted seed row, so it is printed as-is.
  const body = `
    <a class="back" href="/">← all swaps</a>
    <h1>${l.title}</h1>
    <p class="species">${l.species}</p>
    <p class="meta">📍 ${l.location} · posted ${l.created_at}</p>
    <p class="desc">${l.description}</p>

    <div id="share-banner" data-listing="${l.id}"></div>

    <section class="comments">
      <h2>Comments</h2>
      <div id="comments">${commentsHtml}</div>
      <form class="stack" action="/listing/${l.id}/comments" method="post">
        <label>Add a comment
          <textarea name="body" rows="3" placeholder="Say something nice…"></textarea>
        </label>
        <button type="submit">Post comment</button>
      </form>
    </section>`;
  res.send(layout(l.title, body, req));
});

// Post a comment (body is stored verbatim — see FIX 4)
app.post('/listing/:id/comments', (req, res) => {
  const id = Number(req.params.id);
  const author = currentUser(req) || 'guest';
  const body = req.body.body || '';
  run(`INSERT INTO comments (listing_id, author, body, created_at) VALUES (?, ?, ?, ?)`, [
    id,
    author,
    body,
    new Date().toISOString().slice(0, 16).replace('T', ' '),
  ]);
  res.redirect(`/listing/${id}`);
});

// ---------------------------------------------------------------------------
// FIX 5 (part B): NO CONTENT SECURITY POLICY
// There is no Content-Security-Policy header anywhere in this app, so the
// browser will run injected inline scripts and event handlers.
// Fix idea: send a restrictive CSP on every response (a small middleware,
//   added ABOVE the routes, is the natural place). This app keeps all of its
//   JS in /app.js and all CSS in /styles.css, so a 'self'-based policy with
//   no 'unsafe-inline' will not break anything it legitimately does.
// ---------------------------------------------------------------------------

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`GreenThumb (vulnerable build) → http://localhost:${PORT}`);
  });
});
