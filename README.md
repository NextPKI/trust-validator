# NextPKI Trust Validator

NextPKI Trust Validator is a Go-based tool for validating X.509 certificate chains against a trusted root store. It automatically downloads the latest CA trust store, updates a Postgres database, and checks the trust status of certificates stored in the database. It can run as a one-shot tool or as a daemon with periodic validation and a health check endpoint.

## Features
- Downloads and parses the latest CA trust store (from curl.se)
- Stores trusted root certificates in a Postgres table (table name is configurable)
- Validates certificate chains from a specified certificates table
- Updates trust status and last checked timestamp in the database
- Optionally sends alerts for untrusted certificates via webhook
- Refreshes the trust store only if expired (expiration time is configurable)
- Table names and key behaviors are controlled by environment variables
- OCSP checks can be enabled or disabled
- Provides a health check HTTP endpoint (`/` on port 8080) in daemon mode

## Quick Start
1. Clone the repository and enter the directory:
   ```sh
   git clone https://github.com/NextPKI/trust-validator.git
   cd validator
   ```
2. Copy the example environment file and edit as needed:
   ```sh
   cp .env.example .env
   # Edit .env to set your database, webhook, and table settings
   ```
3. Build the tool:
   ```sh
   make
   ```
4. Run the validator once:
   ```sh
   ./trust-validator
   ```
5. Run as a daemon (with health check):
   ```sh
   DAEMON_MODE=true ./trust-validator
   # or set DAEMON_MODE in your environment/.env
   ```

## Environment Variables
- `DATABASE_URL`: Postgres connection string (required)
- `ALERT_WEBHOOK_URL`: (Optional) Webhook URL for untrusted certificate alerts
- `USE_WEBHOOK`: Set to `true` or `false` to enable/disable webhook alerts (default: true)
- `TRUSTSTORE_EXPIRATION_SECONDS`: Number of seconds before the trust store is considered expired and will be refreshed (default: 86400)
- `TRUST_STORE_TABLE`: Name of the trust store table (default: `trust_store`)
- `CERTIFICATES_TABLE`: Name of the certificates table (default: `certificates`)
- `CHECK_OCSP`: Set to `true` or `false` to enable/disable OCSP checks (default: true)
- `DAEMON_MODE`: Set to `true` to enable daemon mode (runs in a loop and exposes health check endpoint)
- `VALIDATOR_INTERVAL_SECONDS`: Interval in seconds between runs in daemon mode (default: 1800)

## Health Check Endpoint
When running in daemon mode, the validator exposes an HTTP health check endpoint at `http://localhost:8080/` that returns `200 OK` and `ok` in the body. This is useful for verifying the service is running.

## Makefile Targets
- `make` or `make build`: Build the binary
- `make clean`: Remove the built binary

## License

This project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.
