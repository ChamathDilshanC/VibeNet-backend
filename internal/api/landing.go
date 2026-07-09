package api

import (
	"net/http"
	"strings"
)

// LandingHandler serves a self-contained HTML landing / API documentation page at the
// service root ("/"), so a browser hitting the bare domain sees a professional overview
// instead of a 404. Version and environment are injected at construction time.
func LandingHandler(version, environment string) http.HandlerFunc {
	page := strings.ReplaceAll(landingHTML, "{{VERSION}}", version)
	page = strings.ReplaceAll(page, "{{ENV}}", environment)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(page))
	}
}

// NotFoundHandler returns a clean JSON 404 that points callers at the documentation root,
// replacing Chi's default plain-text "404 page not found".
func NotFoundHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "route not found",
			"docs":  "/",
		})
	}
}

const landingHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>VibeNet API — Secure Real-Time Chat Backend</title>
<style>
  :root {
    --bg: #0b0e14;
    --panel: #141925;
    --panel-2: #1b2130;
    --border: #263041;
    --text: #e6e9ef;
    --muted: #8a93a6;
    --accent: #6E56CF;
    --accent-2: #00ADD8;
    --green: #2EA44F;
    --amber: #d29922;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: radial-gradient(1200px 600px at 70% -10%, rgba(110,86,207,0.18), transparent 60%), var(--bg);
    color: var(--text);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { max-width: 920px; margin: 0 auto; padding: 48px 24px 80px; }
  .badges { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 28px; }
  .badge {
    font-size: 12px; letter-spacing: .3px; padding: 5px 11px; border-radius: 999px;
    border: 1px solid var(--border); background: var(--panel); color: var(--muted);
  }
  .badge.dot::before {
    content: ""; display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: var(--green); margin-right: 7px; vertical-align: middle;
    box-shadow: 0 0 0 3px rgba(46,164,79,0.18);
  }
  h1 {
    font-size: 40px; line-height: 1.1; margin: 0 0 12px;
    background: linear-gradient(92deg, var(--text), var(--accent-2));
    -webkit-background-clip: text; background-clip: text; color: transparent;
  }
  .lead { font-size: 18px; color: var(--muted); max-width: 640px; margin: 0 0 28px; }
  .cta { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 44px; }
  .btn {
    display: inline-flex; align-items: center; gap: 8px; text-decoration: none;
    font-weight: 600; font-size: 14px; padding: 11px 18px; border-radius: 10px;
    border: 1px solid var(--border); color: var(--text); background: var(--panel);
    transition: transform .12s ease, border-color .12s ease;
  }
  .btn:hover { transform: translateY(-1px); border-color: var(--accent); }
  .btn.primary { background: linear-gradient(92deg, var(--accent), #8b7fd6); border-color: transparent; }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 1.2px; color: var(--muted); margin: 40px 0 14px; }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 13px 16px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .6px; }
  tr:last-child td { border-bottom: none; }
  td.method { font-weight: 700; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .m-get { color: var(--accent-2); }
  .m-post { color: var(--green); }
  .m-put { color: var(--amber); }
  code { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 13px; color: var(--text); }
  .pill { font-size: 11px; padding: 2px 8px; border-radius: 6px; border: 1px solid var(--border); color: var(--muted); }
  .pill.jwt { color: var(--accent); border-color: rgba(110,86,207,.5); }
  .note {
    margin-top: 40px; padding: 18px 20px; border-radius: 12px;
    border: 1px solid rgba(46,164,79,.35); background: rgba(46,164,79,.07); color: var(--text); font-size: 14px;
  }
  footer { margin-top: 56px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--muted); font-size: 13px; }
  footer a { color: var(--accent-2); text-decoration: none; }
  @media (max-width: 560px) {
    h1 { font-size: 30px; }
    th:nth-child(3), td:nth-child(3) { display: none; }
  }
</style>
</head>
<body>
  <div class="wrap">
    <div class="badges">
      <span class="badge dot">Operational</span>
      <span class="badge">v{{VERSION}}</span>
      <span class="badge">env: {{ENV}}</span>
      <span class="badge">Go · Chi · WebSocket</span>
    </div>

    <h1>VibeNet API</h1>
    <p class="lead">
      The blind-router backend for an end-to-end encrypted, real-time chat platform.
      It authenticates users, relays opaque ciphertext, and stores encrypted payloads —
      but never decrypts, inspects, or logs plain-text messages.
    </p>

    <div class="cta">
      <a class="btn primary" href="/health">● Live Health Check</a>
      <a class="btn" href="https://github.com/ChamathDilshanC/VibeNet-backend" target="_blank" rel="noopener">GitHub Repository</a>
    </div>

    <h2>REST Endpoints</h2>
    <div class="card">
      <table>
        <thead>
          <tr><th>Method</th><th>Endpoint</th><th>Auth</th><th>Description</th></tr>
        </thead>
        <tbody>
          <tr><td class="method m-get">GET</td><td><code>/health</code></td><td>—</td><td>Deep health check — pings PostgreSQL &amp; DynamoDB</td></tr>
          <tr><td class="method m-post">POST</td><td><code>/api/auth/register</code></td><td>—</td><td>Register with username, password &amp; E2EE public key</td></tr>
          <tr><td class="method m-post">POST</td><td><code>/api/auth/login</code></td><td>—</td><td>Standard login — returns a signed JWT</td></tr>
          <tr><td class="method m-get">GET</td><td><code>/api/auth/google/login</code></td><td>—</td><td>Redirect to the Google OAuth consent screen</td></tr>
          <tr><td class="method m-get">GET</td><td><code>/api/auth/google/callback</code></td><td>—</td><td>Handle the OAuth callback and return a JWT</td></tr>
          <tr><td class="method m-put">PUT</td><td><code>/api/user/public-key</code></td><td><span class="pill jwt">JWT</span></td><td>Upload or update the caller's E2EE public key</td></tr>
          <tr><td class="method m-put">PUT</td><td><code>/api/user/settings/pin-toggle</code></td><td><span class="pill jwt">JWT</span></td><td>Enable / disable the anti-spam chat PIN</td></tr>
          <tr><td class="method m-get">GET</td><td><code>/api/user/my-pin</code></td><td><span class="pill jwt">JWT</span></td><td>Return the caller's active 4-digit PIN</td></tr>
          <tr><td class="method m-get">GET</td><td><code>/api/users/search</code></td><td><span class="pill jwt">JWT</span></td><td>Search users by username for chat discovery</td></tr>
          <tr><td class="method m-get">GET</td><td><code>/api/users/{id}/key</code></td><td><span class="pill jwt">JWT</span></td><td>Fetch a user's public key (PIN required if mandated)</td></tr>
          <tr><td class="method m-get">GET</td><td><code>/api/messages/{chatRoomID}</code></td><td><span class="pill jwt">JWT</span></td><td>Fetch cached encrypted message history for a chat room (participants only)</td></tr>
        </tbody>
      </table>
    </div>

    <h2>Real-Time WebSocket</h2>
    <div class="card">
      <table>
        <tbody>
          <tr><td class="method m-get">WS</td><td><code>/ws?token=&lt;jwt&gt;</code></td><td><span class="pill jwt">JWT</span></td><td>Upgrade to a WebSocket to send &amp; receive encrypted message frames</td></tr>
        </tbody>
      </table>
    </div>

    <div class="note">
      🔐 <strong>Content-blind by design.</strong> Encryption and decryption happen entirely on the
      client with TweetNaCl.js. The server routes and persists only ciphertext and cryptographic
      metadata (nonce) — plain-text is never stored, logged, or processed server-side.
    </div>

    <footer>
      VibeNet — Secure by design · Encrypted end-to-end · Built on the AWS Free Tier<br/>
      Architected by <a href="https://github.com/ChamathDilshanC" target="_blank" rel="noopener">Chamath Dilshan</a>
    </footer>
  </div>
</body>
</html>`
