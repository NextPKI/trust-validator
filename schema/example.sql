CREATE TABLE trust_store (
  fingerprint TEXT PRIMARY KEY,
  subject TEXT,
  updated_at TIMESTAMP WITH TIME ZONE
);

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE cd_certs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificates TEXT[] NOT NULL, -- PEM encoded DER certificates (leaf, intermediate, root)
    trusted BOOLEAN DEFAULT FALSE,
    last_checked TIMESTAMP,
    ocsp_checked BOOLEAN,
    ocsp_error TEXT
);
