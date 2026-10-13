# imgshare

Fake image sharing site to deanonymize weirdos.

Cloudflare Workers serves the original landing page, static assets and tracking
pixel (`/cG9vcAo.gif`). D1 stores tracking rows with their original time, IP and
header fields; `/track` shows the newest 100. Cookie, authorization and API-key
headers are redacted before storage and display. Unknown paths return real 404s.

`npm ci`, `npm test` and `npm run check:deploy` validate the port. Production
publishing uses Cloudflare native Git builds from `main`, with previews disabled.
Set and save that production branch explicitly in Cloudflare after connecting the
repository; onboarding can retain the old default branch in its cached metadata.
The separate `staging` environment uses its own D1 and session secret. Production
tracking is enabled after the old tracking snapshot, router freeze and D1 state
were reconciled as empty. The source User model has no application writers.

`SESSION_SECRET` is a stable Cloudflare secret; the source regenerated its issuer
on every process start, so users sign in again after migration. Signed login keeps
the original 600-second message bucket, 15-minute JWT and anonymous cookie paths.
`AUTH_DOMAIN` now matches the intended host instead of the unrelated hardcoded
Heroku domain. This retains the old bucket replay behavior, not single-use SIWE.

The original `/secret` GST gate needs an RPC endpoint (`RPC_URL`, formerly `web3`).
Heroku had no such variable configured. It fails closed with 503 until configured;
tests use a mock and never submit a transaction. The original Python deployment
remains in Git history and `heroku-recovery/requirements.txt` for recovery.


Cutover uses the exact ordinary Worker route `imgshare.app/*` over the preserved
proxied Heroku CNAME. Keep the original source frozen. Before restoring Heroku
writes after Cloudflare has accepted tracking data, first freeze Cloudflare and
reverse-transfer all accepted records into SQLite; a routing-only rollback loses
new data. Private recovery exports must never be committed to this repository.
