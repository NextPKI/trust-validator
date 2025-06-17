# Changelog

### 06/18/2025

- To address a trademark request, we have renamed our project from ultraPKI to nextPKI. You can now find us at github.com/nextpki 🤡

### 05/30/2025

- Added daemon mode: The validator can now run in a loop with an interval specified by the `VALIDATOR_INTERVAL_SECONDS` environment variable (default: 1800 seconds). Enable with `DAEMON_MODE=true`.
- Environment variable `USE_OCSP` renamed to `CHECK_OCSP` for clarity. All code, docs, and env files updated.
- Improved environment variable handling: `DATABASE_URL` is now always required and checked at startup.
- Improved deploy.sh to strip quotes from secret values before setting them.
- Cleaned up Makefile and README to only list actual build targets.
