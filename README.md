# HACK_LUNCH // Hacktoberfest '26

Retro CRT meal-allocation terminal with two entry routes:

- Students authenticate with GitHub OAuth, using a server-side authorization-code exchange, `state`, and an HttpOnly session cookie.
- Faculty can enter any non-empty name to create a server-side session. This is self-declared identity, not roster verification.
- Both routes converge on the same ten-option vegetarian meal matrix. The server permits one validated meal submission per authenticated or self-declared identity, writes it to the configured Google Sheets endpoint, and only then returns a confirmation token.

## Run

1. Create a local `.env` file (it is intentionally excluded from Git) and set `PORT`, `APP_ORIGIN`, `SESSION_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`, and `GOOGLE_SHEETS_ENDPOINT`. Set `GOOGLE_SHEETS_BEARER_TOKEN` only if your endpoint requires it.
2. Register a GitHub OAuth App. Its callback URL must exactly equal `GITHUB_REDIRECT_URI`.
3. Set `GOOGLE_SHEETS_ENDPOINT` to your HTTPS Apps Script/webhook URL. Faculty access accepts any non-empty name, so use roster verification separately if faculty identity must be restricted. The endpoint receives a JSON record with timestamp, role, identity, GitHub username, name, meal, status, and token. No endpoint is supplied by this project.
4. Start the terminal:

   ```bash
   npm start
   ```

5. Open `http://localhost:3000`.

## Production notes

Set `APP_ORIGIN` to the public HTTPS origin, use a high-entropy `SESSION_SECRET`, and run behind TLS. Session cookies are signed, HttpOnly, and SameSite=Lax. The in-memory sessions and duplicate-submission store are deliberate for a simple runnable project; for a multi-instance production deployment, move both to a shared database/redis store and make the unique identity constraint transactional.
