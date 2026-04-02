CREATE TABLE IF NOT EXISTS osv_vulnerabilities (
    id VARCHAR(255) PRIMARY KEY,
    modified TIMESTAMP WITH TIME ZONE NOT NULL,
    published TIMESTAMP WITH TIME ZONE,
    schema_version VARCHAR(50),
    data JSONB NOT NULL,
    inserted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index on the JSONB array of 'aliases' to quickly search by CVE or other IDs
CREATE INDEX IF NOT EXISTS idx_osv_aliases ON osv_vulnerabilities USING GIN ((data -> 'aliases'));

-- Index on the JSONB array of 'affected' for searching by package ecology/name
CREATE INDEX IF NOT EXISTS idx_osv_affected ON osv_vulnerabilities USING GIN ((data -> 'affected'));

-- Index on modified date for sorting
CREATE INDEX IF NOT EXISTS idx_osv_modified ON osv_vulnerabilities (modified);
