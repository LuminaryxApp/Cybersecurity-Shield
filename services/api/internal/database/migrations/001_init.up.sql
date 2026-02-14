-- Enable TimescaleDB
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Organizations
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_id VARCHAR(255) UNIQUE NOT NULL,
    org_id UUID NOT NULL REFERENCES organizations(id),
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_keycloak ON users(keycloak_id);

-- Agents
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    last_heartbeat TIMESTAMPTZ,
    config JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_org ON agents(org_id);

-- Alert Rules
CREATE TABLE alert_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    name VARCHAR(255) NOT NULL,
    severity_threshold VARCHAR(50) NOT NULL DEFAULT 'medium',
    channels JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alert_rules_org ON alert_rules(org_id);

-- Alerts
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id),
    agent_id UUID REFERENCES agents(id),
    severity VARCHAR(50) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    llm_explanation TEXT,
    llm_remediation TEXT,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    assignee_id UUID REFERENCES users(id),
    source_events JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_org ON alerts(org_id);
CREATE INDEX idx_alerts_status ON alerts(org_id, status);
CREATE INDEX idx_alerts_severity ON alerts(org_id, severity);

-- Events (TimescaleDB hypertable)
CREATE TABLE events (
    time TIMESTAMPTZ NOT NULL,
    org_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    source VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL DEFAULT 'info',
    risk_score REAL NOT NULL DEFAULT 0,
    summary VARCHAR(500),
    payload JSONB NOT NULL DEFAULT '{}',
    FOREIGN KEY (org_id) REFERENCES organizations(id)
);

SELECT create_hypertable('events', 'time');
CREATE INDEX idx_events_org ON events(org_id, time DESC);
CREATE INDEX idx_events_source ON events(org_id, source, time DESC);

-- Metrics (TimescaleDB hypertable)
CREATE TABLE metrics (
    time TIMESTAMPTZ NOT NULL,
    org_id UUID NOT NULL,
    agent_id UUID NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    metric_value DOUBLE PRECISION NOT NULL,
    tags JSONB NOT NULL DEFAULT '{}'
);

SELECT create_hypertable('metrics', 'time');
CREATE INDEX idx_metrics_org ON metrics(org_id, metric_name, time DESC);

-- Threat Scores (TimescaleDB hypertable)
CREATE TABLE threat_scores (
    time TIMESTAMPTZ NOT NULL,
    org_id UUID NOT NULL,
    score REAL NOT NULL,
    factors JSONB NOT NULL DEFAULT '{}'
);

SELECT create_hypertable('threat_scores', 'time');
CREATE INDEX idx_threat_scores_org ON threat_scores(org_id, time DESC);
