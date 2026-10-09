-- ============ IOCS (core, deduplicated) ============
CREATE TABLE IF NOT EXISTS iocs (
    id            BIGSERIAL PRIMARY KEY,
    ioc_type      TEXT NOT NULL,        -- ip, domain, url, md5, sha256, etc.
    value         TEXT NOT NULL,
    malware       TEXT,                 -- kis malware se juda (threatfox se)
    threat_type   TEXT,                 -- botnet_cc, payload, etc.
    reason        TEXT,                 -- kyun malicious (LLM/threatfox se)
    confidence    INT DEFAULT 50,
    first_seen    TIMESTAMPTZ DEFAULT now(),
    last_seen     TIMESTAMPTZ DEFAULT now(),
    times_seen    INT DEFAULT 1,
    is_active     BOOLEAN DEFAULT true,
    risk_score    INT DEFAULT 0,
    risk_level    TEXT DEFAULT 'LOW',
    UNIQUE (ioc_type, value)            -- yahi dedup: same IOC ek hi baar
);

-- ============ IOC ENRICHMENT ============
CREATE TABLE IF NOT EXISTS ioc_enrichment (
    ioc_id        BIGINT PRIMARY KEY REFERENCES iocs(id) ON DELETE CASCADE,
    abuse_score   INT,
    abuse_reports INT,
    abuse_country TEXT,
    abuse_isp     TEXT,
    abuse_usage   TEXT,
    shodan_ports  TEXT,
    shodan_org    TEXT,
    vt_malicious  INT,
    vt_suspicious INT,
    vt_reputation INT,
    vt_last_analysis TIMESTAMPTZ,
    vt_link       TEXT,
    greynoise_noise BOOLEAN,
    greynoise_riot BOOLEAN,
    greynoise_classification TEXT,
    greynoise_name TEXT,
    greynoise_last_seen DATE,
    greynoise_link TEXT,
    enriched_at   TIMESTAMPTZ DEFAULT now()
);

-- ============ SIGHTINGS (har baar dikhne ka record) ============
CREATE TABLE IF NOT EXISTS ioc_sightings (
    id           BIGSERIAL PRIMARY KEY,
    ioc_id       BIGINT REFERENCES iocs(id) ON DELETE CASCADE,
    source       TEXT NOT NULL,         -- kahan dikha
    seen_at      TIMESTAMPTZ DEFAULT now(),
    raw_item_id  BIGINT                 -- kis pull se aaya
);

-- ============ CVES ============
CREATE TABLE IF NOT EXISTS cves (
    id             BIGSERIAL PRIMARY KEY,
    cve_id         TEXT UNIQUE NOT NULL,
    cvss_score     NUMERIC,
    severity       TEXT,
    description    TEXT,
    kev_listed     BOOLEAN DEFAULT false,  -- CISA KEV mein hai? (actively exploited)
    published      TIMESTAMPTZ,
    first_seen     TIMESTAMPTZ DEFAULT now(),
    last_seen      TIMESTAMPTZ DEFAULT now()
);

-- ============ ARTICLES ============
CREATE TABLE IF NOT EXISTS articles (
    id           BIGSERIAL PRIMARY KEY,
    title        TEXT NOT NULL,
    link         TEXT UNIQUE,
    published    TEXT,
    summary      TEXT,                  -- LLM ka 2-line summary
    apt_groups   TEXT[],                -- nikale gaye APT groups
    malware      TEXT[],                -- nikale gaye malware
    fetched_at   TIMESTAMPTZ DEFAULT now()
);

-- ============ APT GROUPS ============
CREATE TABLE IF NOT EXISTS apt_groups (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT UNIQUE NOT NULL,
    first_seen   TIMESTAMPTZ DEFAULT now(),
    last_seen    TIMESTAMPTZ DEFAULT now(),
    times_seen   INT DEFAULT 1
);

-- Indexes for speed
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type);
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(is_active);
CREATE INDEX IF NOT EXISTS idx_iocs_malware ON iocs(malware);
CREATE INDEX IF NOT EXISTS idx_sightings_ioc ON ioc_sightings(ioc_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);

ALTER TABLE apt_groups
    ADD COLUMN IF NOT EXISTS description TEXT,
    ADD COLUMN IF NOT EXISTS aliases TEXT[],
    ADD COLUMN IF NOT EXISTS target_sectors TEXT[],
    ADD COLUMN IF NOT EXISTS origin_country TEXT,
    ADD COLUMN IF NOT EXISTS mitre_id TEXT,
    ADD COLUMN IF NOT EXISTS mitre_url TEXT,
    ADD COLUMN IF NOT EXISTS main_article_link TEXT,
    ADD COLUMN IF NOT EXISTS main_article_title TEXT;

ALTER TABLE cves
    ADD COLUMN IF NOT EXISTS "references" TEXT[],
    ADD COLUMN IF NOT EXISTS affected_products TEXT[],
    ADD COLUMN IF NOT EXISTS vendor_project TEXT,
    ADD COLUMN IF NOT EXISTS product TEXT,
    ADD COLUMN IF NOT EXISTS vulnerability_name TEXT,
    ADD COLUMN IF NOT EXISTS required_action TEXT,
    ADD COLUMN IF NOT EXISTS due_date DATE,
    ADD COLUMN IF NOT EXISTS ransomware_use TEXT,
    ADD COLUMN IF NOT EXISTS notes TEXT;

ALTER TABLE articles
    ADD COLUMN IF NOT EXISTS source TEXT,
    ADD COLUMN IF NOT EXISTS excerpt TEXT;

ALTER TABLE ioc_enrichment
    ADD COLUMN IF NOT EXISTS vt_malicious INT,
    ADD COLUMN IF NOT EXISTS vt_suspicious INT,
    ADD COLUMN IF NOT EXISTS vt_reputation INT,
    ADD COLUMN IF NOT EXISTS vt_last_analysis TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS vt_link TEXT,
    ADD COLUMN IF NOT EXISTS greynoise_noise BOOLEAN,
    ADD COLUMN IF NOT EXISTS greynoise_riot BOOLEAN,
    ADD COLUMN IF NOT EXISTS greynoise_classification TEXT,
    ADD COLUMN IF NOT EXISTS greynoise_name TEXT,
    ADD COLUMN IF NOT EXISTS greynoise_last_seen DATE,
    ADD COLUMN IF NOT EXISTS greynoise_link TEXT;

CREATE TABLE IF NOT EXISTS apt_techniques (
    group_name     TEXT REFERENCES apt_groups(name) ON DELETE CASCADE,
    mitre_group_id TEXT NOT NULL,
    technique_id   TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    tactics        TEXT[],
    source_url     TEXT,
    updated_at     TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (group_name, technique_id)
);

-- ATT&CK software (malware and tools) and the groups that use it.  These
-- relationships come directly from MITRE STIX and form a trustworthy bridge
-- between feed malware labels and threat actors.
CREATE TABLE IF NOT EXISTS attack_software (
    name          TEXT PRIMARY KEY,
    mitre_id      TEXT UNIQUE NOT NULL,
    software_type TEXT NOT NULL,
    description   TEXT,
    aliases       TEXT[],
    mitre_url     TEXT,
    updated_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS apt_software (
    group_name     TEXT REFERENCES apt_groups(name) ON DELETE CASCADE,
    software_name  TEXT REFERENCES attack_software(name) ON DELETE CASCADE,
    mitre_group_id TEXT NOT NULL,
    mitre_software_id TEXT NOT NULL,
    source_url     TEXT,
    updated_at     TIMESTAMPTZ DEFAULT now(),
    PRIMARY KEY (group_name, software_name)
);

-- Unified evidence view. Every edge remains traceable to a stored record or
-- MITRE mapping; the UI never invents correlations from name similarity alone.
CREATE OR REPLACE VIEW intelligence_relationships AS
SELECT 'ioc'::TEXT AS subject_type, i.value AS subject_value,
       'associated_with'::TEXT AS predicate, 'malware'::TEXT AS object_type,
       i.malware AS object_value, 'ioc_record'::TEXT AS evidence_source,
       i.first_seen, i.last_seen, i.confidence
FROM iocs i WHERE NULLIF(trim(i.malware), '') IS NOT NULL
UNION ALL
SELECT 'ioc', i.value, 'observed_by', 'source', s.source, 'sighting',
       s.seen_at, s.seen_at, i.confidence
FROM ioc_sightings s JOIN iocs i ON i.id=s.ioc_id
UNION ALL
SELECT 'apt', t.group_name, 'uses', 'technique',
       t.technique_id || ' · ' || t.technique_name, 'mitre_attack',
       t.updated_at, t.updated_at, 100
FROM apt_techniques t
UNION ALL
SELECT 'apt', s.group_name, 'uses', 'malware', s.software_name,
       'mitre_attack', s.updated_at, s.updated_at, 100
FROM apt_software s
UNION ALL
SELECT 'article', a.id::TEXT, 'mentions', 'apt', actor,
       COALESCE(a.source, 'article'), a.fetched_at, a.fetched_at, 70
FROM articles a CROSS JOIN LATERAL unnest(COALESCE(a.apt_groups, ARRAY[]::TEXT[])) actor
UNION ALL
SELECT 'article', a.id::TEXT, 'mentions', 'malware', family,
       COALESCE(a.source, 'article'), a.fetched_at, a.fetched_at, 70
FROM articles a CROSS JOIN LATERAL unnest(COALESCE(a.malware, ARRAY[]::TEXT[])) family
UNION ALL
SELECT 'article', a.id::TEXT, 'mentions', 'cve', upper(hit[1]),
       COALESCE(a.source, 'article'), a.fetched_at, a.fetched_at, 70
FROM articles a
CROSS JOIN LATERAL regexp_matches(
  concat_ws(' ', a.title, a.summary, a.excerpt), '(CVE-[0-9]{4}-[0-9]{4,7})', 'gi'
) hit;

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id           BIGSERIAL PRIMARY KEY,
    started_at   TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'RUNNING',
    log_path     TEXT
);

CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    bool_value BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT now()
);

-- SIEM events arrive through a separately authenticated ingestion endpoint.
-- The original JSON is retained for auditability; normalized columns support
-- fast dashboards without making the event writer a database user.
CREATE TABLE IF NOT EXISTS siem_events (
    id              BIGSERIAL PRIMARY KEY,
    source          TEXT NOT NULL,
    external_id     TEXT NOT NULL,
    rule_id         TEXT,
    rule_level      INT,
    title           TEXT,
    agent_name      TEXT,
    event_timestamp TIMESTAMPTZ,
    raw_event       JSONB NOT NULL,
    match_count     INT NOT NULL DEFAULT 0,
    ingested_at     TIMESTAMPTZ DEFAULT now(),
    UNIQUE (source, external_id)
);

CREATE TABLE IF NOT EXISTS siem_matches (
    id            BIGSERIAL PRIMARY KEY,
    event_id      BIGINT NOT NULL REFERENCES siem_events(id) ON DELETE CASCADE,
    entity_type   TEXT NOT NULL CHECK (entity_type IN ('ioc', 'cve')),
    entity_value  TEXT NOT NULL,
    ioc_id        BIGINT REFERENCES iocs(id) ON DELETE SET NULL,
    cve_record_id BIGINT REFERENCES cves(id) ON DELETE SET NULL,
    match_field   TEXT,
    risk_score    INT,
    risk_level    TEXT,
    created_at    TIMESTAMPTZ DEFAULT now(),
    UNIQUE (event_id, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_articles_published ON articles (fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves (published DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_iocs_risk ON iocs (risk_level);
CREATE INDEX IF NOT EXISTS idx_apt_techniques_group ON apt_techniques (group_name);
CREATE INDEX IF NOT EXISTS idx_apt_techniques_tactics ON apt_techniques USING GIN (tactics);
CREATE INDEX IF NOT EXISTS idx_attack_software_aliases ON attack_software USING GIN (aliases);
CREATE INDEX IF NOT EXISTS idx_apt_software_group ON apt_software (group_name);
CREATE INDEX IF NOT EXISTS idx_apt_software_name ON apt_software (software_name);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started ON pipeline_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_siem_events_ingested ON siem_events (ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_siem_events_level ON siem_events (rule_level DESC);
CREATE INDEX IF NOT EXISTS idx_siem_matches_event ON siem_matches (event_id);
CREATE INDEX IF NOT EXISTS idx_siem_matches_value ON siem_matches (entity_value);
