# HACK_LUNCH // Hacktoberfest '26

Retro CRT meal-allocation terminal with two verified routes:

- Students authenticate with GitHub OAuth, using a server-side authorization-code exchange, `state`, and an HttpOnly session cookie.
- Faculty names must be present in the configured roster before a server-side session is created.
- Both routes converge on the same ten-option vegetarian meal matrix. The server permits exactly one validated meal submission per verified identity, writes it to the configured Google Sheets endpoint, and only then returns a confirmation token.

## Run

1. Copy `.env.example` to `.env` and set every required value.
2. Register a GitHub OAuth App. Its callback URL must exactly equal `GITHUB_REDIRECT_URI`.
3. Configure `FACULTY_ROSTER_NAMES` with the approved names and set `GOOGLE_SHEETS_ENDPOINT` to your HTTPS Apps Script/webhook URL. The endpoint receives a JSON record with timestamp, role, identity, GitHub username, name, meal, status, and token. No endpoint is supplied by this project.
4. Start the terminal:

   ```bash
   npm start
   ```

5. Open `http://localhost:3000`.

## Production notes

Set `APP_ORIGIN` to the public HTTPS origin, use a high-entropy `SESSION_SECRET`, and run behind TLS. Session cookies are signed, HttpOnly, and SameSite=Lax. The in-memory sessions and duplicate-submission store are deliberate for a simple runnable project; for a multi-instance production deployment, move both to a shared database/redis store and make the unique identity constraint transactional.
