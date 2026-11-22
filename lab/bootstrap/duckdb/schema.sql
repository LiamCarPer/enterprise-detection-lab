CREATE TABLE IF NOT EXISTS runs (
    run_id VARCHAR PRIMARY KEY,
    started_at TIMESTAMP NOT NULL,
    finished_at TIMESTAMP,
    git_sha VARCHAR,
    command VARCHAR NOT NULL,
    status VARCHAR NOT NULL
);

CREATE TABLE IF NOT EXISTS validation_results (
    run_id VARCHAR NOT NULL,
    artifact_type VARCHAR NOT NULL,
    artifact_id VARCHAR NOT NULL,
    status VARCHAR NOT NULL,
    errors INTEGER NOT NULL DEFAULT 0,
    warnings INTEGER NOT NULL DEFAULT 0,
    checked_at TIMESTAMP NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS lab_status (
    service VARCHAR NOT NULL,
    state VARCHAR NOT NULL,
    url VARCHAR,
    detail VARCHAR,
    checked_at TIMESTAMP NOT NULL DEFAULT current_timestamp
);

CREATE TABLE IF NOT EXISTS metrics (
    detection_id VARCHAR NOT NULL,
    measured_at TIMESTAMP NOT NULL,
    precision DOUBLE NOT NULL,
    recall DOUBLE NOT NULL,
    false_positive_rate DOUBLE NOT NULL,
    latency_ms_p50 DOUBLE NOT NULL,
    latency_ms_p95 DOUBLE NOT NULL,
    sample_size INTEGER NOT NULL,
    limitations VARCHAR
);
