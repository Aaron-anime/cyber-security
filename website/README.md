# Website — Cyber Security Control Center

This folder contains the static front-end for the Cyber Security Control Center demo.

Quick local preview (Python 3):

```bash
cd website
python -m http.server 8000
# then open http://localhost:8000 in your browser
```

Or use Node.js `serve` if you have it installed:

```bash
npx serve website
```

Notes:
- The front-end expects backend endpoints under `/api/*` for some features (threat feed, scan, hashes). If those aren't running, the UI will still function for demos and local interactions.
- Demo credentials were removed from `login.html` for security.
- Accessibility improvements: skip links, focus outlines, ARIA attributes, and mobile navigation.

If you want, I can add a simple dev server script or wire up the `api/` Python backend to run together with the website.
