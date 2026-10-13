# Imgshare Cloudflare migration

Use focused commits and native Cloudflare Git builds. Credentials belong in
Cloudflare, never GitHub. Preview builds remain disabled; staging uses a separate
D1 database and session secret. Preserve the original Heroku source and slug.
Do not restart the old dyno before its ephemeral tracking data is reconciled.
Tests use disposable wallets, local D1 and mocked RPC, with no transactions.
Tracking must not store or display authentication, cookie or API-key headers.
