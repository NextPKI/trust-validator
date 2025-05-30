package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/ocsp"
)

const trustStoreURL = "https://curl.se/ca/cacert.pem"

// main is the entry point of the application. It connects to the database, updates the trust store, and validates certificates.
func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, continuing with environment variables")
	}

	mustGetenv := func(key string) string {
		val := os.Getenv(key)
		if val == "" {
			log.Fatalf("Missing required environment variable: %s", key)
		}
		return val
	}

	daemonMode := false
	if v := os.Getenv("DAEMON_MODE"); strings.ToLower(v) == "true" {
		daemonMode = true
	}

	interval := 1800 // default 1800 seconds (30 min)
	if v := os.Getenv("VALIDATOR_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = n
		}
	}

	dbURL := mustGetenv("DATABASE_URL")

	if daemonMode {
		go func() {
			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			})
			log.Println("Starting health check server on :8080 (daemon mode)")
			if err := http.ListenAndServe(":8080", nil); err != nil {
				log.Fatalf("Health check server failed: %v", err)
			}
		}()
	}

	for {
		err := runValidator(dbURL)
		if err != nil {
			log.Printf("Validator run failed: %v", err)
		}
		if !daemonMode {
			break
		}
		log.Printf("Sleeping for %d seconds before next run...", interval)
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func runValidator(dbURL string) error {
	ctx := context.Background()

	useWebhook := true
	if v := os.Getenv("USE_WEBHOOK"); v != "" && strings.ToLower(v) != "true" {
		useWebhook = false
	}
	useOCSP := true
	if v := os.Getenv("CHECK_OCSP"); v != "" && strings.ToLower(v) != "true" {
		useOCSP = false
	}

	truststoreExpiration := 86400 // default 1 day
	if v := os.Getenv("TRUSTSTORE_EXPIRATION_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			truststoreExpiration = n
		}
	}

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		return fmt.Errorf("DB connection error: %v", err)
	}
	defer pool.Close()

	trustStoreTable := os.Getenv("TRUST_STORE_TABLE")
	if trustStoreTable == "" {
		trustStoreTable = "trust_store"
	}
	certificatesTable := os.Getenv("CERTIFICATES_TABLE")
	if certificatesTable == "" {
		certificatesTable = "certificates"
	}

	shouldUpdate, err := shouldUpdateTrustStore(ctx, pool, truststoreExpiration, trustStoreTable)
	if err != nil {
		return fmt.Errorf("Failed to check trust store expiration: %v", err)
	}
	if shouldUpdate {
		if err := updateTrustStore(ctx, pool, trustStoreTable); err != nil {
			return fmt.Errorf("Trust store update failed: %v", err)
		}
	} else {
		log.Println("Trust store is still fresh; skipping update.")
	}

	// Always run validation against the current trust store, even if not refreshed
	if err := validateCertificates(ctx, pool, useWebhook, useOCSP, trustStoreTable, certificatesTable); err != nil {
		return fmt.Errorf("Certificate validation failed: %v", err)
	}
	return nil
}

// shouldUpdateTrustStore checks if the trust store should be updated based on expiration seconds.
func shouldUpdateTrustStore(ctx context.Context, pool *pgxpool.Pool, expirationSeconds int, trustStoreTable string) (bool, error) {
	var lastUpdated time.Time
	err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT MAX(updated_at) FROM %s`, trustStoreTable)).Scan(&lastUpdated)
	if err != nil && err.Error() != "no rows in result set" {
		return true, err // If error, force update
	}
	if lastUpdated.IsZero() {
		return true, nil // No trust store yet
	}
	if time.Since(lastUpdated) > time.Duration(expirationSeconds)*time.Second {
		return true, nil // Expired
	}
	return false, nil // Still fresh
}

// updateTrustStore downloads the latest trust store PEM file, parses all certificates, and updates the trust_store table in the database with their fingerprints and PEM data.
func updateTrustStore(ctx context.Context, pool *pgxpool.Pool, trustStoreTable string) error {
	resp, err := http.Get(trustStoreURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	pemBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		certs = append(certs, cert)
	}

	// Prepare batch insert using pgx.Batch
	batch := &pgx.Batch{}
	for _, cert := range certs {
		fp := sha256.Sum256(cert.Raw)
		hexFP := strings.ToUpper(hex.EncodeToString(fp[:]))
		batch.Queue(fmt.Sprintf(`INSERT INTO %s (fingerprint, subject, certificate_pem, updated_at) VALUES ($1, $2, $3, NOW())`, trustStoreTable),
			hexFP, cert.Subject.String(), encodeToPEM(cert.Raw))
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, fmt.Sprintf(`DELETE FROM %s`, trustStoreTable))
	if err != nil {
		return err
	}

	br := tx.SendBatch(ctx, batch)
	for range certs {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// encodeToPEM encodes a DER-encoded certificate to PEM format and returns it as a string.
func encodeToPEM(derBytes []byte) string {
	var pemBuffer bytes.Buffer
	pem.Encode(&pemBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	return pemBuffer.String()
}

// validateCertificates loads certificates from the database, validates them against the trust store, updates their trust status, and sends alerts for untrusted certificates.
func validateCertificates(ctx context.Context, pool *pgxpool.Pool, useWebhook, useOCSP bool, trustStoreTable, certificatesTable string) error {
	rows, err := pool.Query(ctx, fmt.Sprintf(`SELECT id, certificates FROM %s`, certificatesTable))
	if err != nil {
		return err
	}
	defer rows.Close()

	trustRoots := x509.NewCertPool()
	trustedRows, err := pool.Query(ctx, fmt.Sprintf(`SELECT certificate_pem FROM %s`, trustStoreTable))
	if err != nil {
		return err
	}
	defer trustedRows.Close()

	for trustedRows.Next() {
		var pem string
		if err := trustedRows.Scan(&pem); err != nil {
			return err
		}
		trustRoots.AppendCertsFromPEM([]byte(pem))
	}

	for rows.Next() {
		var id string
		var pemArray []string // text[] from PostgreSQL
		if err := rows.Scan(&id, &pemArray); err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}

		trusted, ocspChecked, ocspErrMsg := validateCertChainWithOCSPInfo(pemArray, trustRoots, useOCSP)

		_, err = pool.Exec(ctx, fmt.Sprintf(`UPDATE %s SET trusted = $1, last_checked = NOW(), ocsp_checked = $2, ocsp_error = $3 WHERE id = $4`, certificatesTable),
			trusted, ocspChecked, ocspErrMsg, id,
		)
		if err != nil {
			log.Printf("Update error: %v", err)
		}

		if !trusted && useWebhook {
			sendAlert(id)
		}
	}
	return nil
}

// validateCertChainWithOCSPInfo validates a certificate chain and returns (trusted, ocspChecked, ocspErrorMsg)
func validateCertChainWithOCSPInfo(pemCerts []string, trustRoots *x509.CertPool, useOCSP bool) (bool, bool, string) {
	if len(pemCerts) == 0 {
		return false, false, "empty certificate chain"
	}

	leafCert, err := parseSingleCert(pemCerts[0])
	if err != nil {
		return false, false, err.Error()
	}

	intermediates := x509.NewCertPool()
	var issuerCert *x509.Certificate
	for i, pem := range pemCerts[1:] {
		intermediate, err := parseSingleCert(pem)
		if err != nil {
			return false, false, err.Error()
		}
		intermediates.AddCert(intermediate)
		if i == 0 {
			issuerCert = intermediate // first intermediate is usually the issuer
		}
	}
	// If no intermediates, try to find issuer in trustRoots (not implemented here)
	if issuerCert == nil && len(pemCerts) > 1 {
		issuerCert, _ = parseSingleCert(pemCerts[1])
	}

	opts := x509.VerifyOptions{
		Roots:         trustRoots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return false, false, "chain validation failed: " + err.Error()
	}

	// OCSP check (only if issuerCert is available)
	if useOCSP && issuerCert != nil {
		ocspValid, err := checkOCSP(leafCert, issuerCert)
		if err != nil {
			return false, false, "ocsp error: " + err.Error()
		}
		if !ocspValid {
			return false, true, "certificate revoked (OCSP)"
		}
		return true, true, ""
	}
	return true, false, ""
}

// parseSingleCert parses a single PEM-encoded certificate and returns the x509.Certificate object.
func parseSingleCert(certData string) (*x509.Certificate, error) {
	certData = strings.TrimSpace(certData)

	// Case 1: PEM detected
	if strings.HasPrefix(certData, "-----BEGIN CERTIFICATE-----") {
		block, _ := pem.Decode([]byte(certData))
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("invalid PEM data")
		}
		return x509.ParseCertificate(block.Bytes)
	}

	// Case 2: base64-encoded DER
	derBytes, err := base64.StdEncoding.DecodeString(certData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 DER data: %w", err)
	}

	return x509.ParseCertificate(derBytes)
}

// sendAlert sends a webhook alert for a certificate that became untrusted.
func sendAlert(certID string) {
	webhookURL := os.Getenv("ALERT_WEBHOOK_URL")
	if webhookURL == "" {
		log.Printf("ALERT_WEBHOOK_URL not set, cannot send alert for certificate %s", certID)
		return
	}
	payload := strings.NewReader(fmt.Sprintf(`{"text":"⚠️ Certificate %s became untrusted!"}`, certID))
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Post(webhookURL, "application/json", payload)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if resp.Body != nil {
				resp.Body.Close()
			}
			return
		}
		if err != nil {
			log.Printf("Failed to send alert for certificate %s (attempt %d): %v", certID, i+1, err)
		} else {
			log.Printf("Alert webhook returned status %d for certificate %s (attempt %d)", resp.StatusCode, certID, i+1)
			if resp.Body != nil {
				resp.Body.Close()
			}
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("Giving up on sending alert for certificate %s after %d attempts", certID, maxRetries)
}

// checkOCSP queries the OCSP responder for the revocation status of a certificate.
// Returns true if the certificate is NOT revoked, false if revoked or unknown.
func checkOCSP(cert, issuer *x509.Certificate) (bool, error) {
	if len(cert.OCSPServer) == 0 {
		return true, nil // No OCSP server, treat as not revoked (or handle as policy)
	}
	req, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return false, err
	}
	resp, err := http.Post(cert.OCSPServer[0], "application/ocsp-request", bytes.NewReader(req))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	ocspResp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return false, err
	}
	if ocspResp.Status == ocsp.Revoked {
		return false, nil
	}
	return true, nil
}
