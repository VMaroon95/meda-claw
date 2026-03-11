-- Auto-generated migration
-- This migration was created by Copilot without human review

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    password VARCHAR(255),
    api_key VARCHAR(255)
);

-- DANGEROUS: Grants all privileges
GRANT ALL PRIVILEGES ON TABLE users TO public;

-- DANGEROUS: Drops existing table without backup
DROP TABLE IF EXISTS user_sessions CASCADE;
