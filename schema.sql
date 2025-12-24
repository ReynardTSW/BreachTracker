-- BreachTracker database schema (PostgreSQL-ready)

-- Table: breach_incidents
CREATE TABLE IF NOT EXISTS breach_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(50) UNIQUE NOT NULL,
    incident_date DATE NOT NULL,
    discovered_date DATE NOT NULL,
    reported_date DATE,
    resolved_date DATE,
    breach_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    root_cause VARCHAR(100) NOT NULL,
    affected_records INTEGER NOT NULL,
    data_types TEXT[] NOT NULL,
    business_unit VARCHAR(100) NOT NULL,
    response_time_hours INTEGER,
    status VARCHAR(50) NOT NULL,
    description TEXT NOT NULL,
    remediation_actions TEXT,
    lessons_learned TEXT,
    pdpc_notification_required BOOLEAN DEFAULT false,
    pdpc_notified BOOLEAN DEFAULT false,
    dpo_guidance_issued BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_incident_date ON breach_incidents (incident_date);
CREATE INDEX IF NOT EXISTS idx_business_unit ON breach_incidents (business_unit);
CREATE INDEX IF NOT EXISTS idx_severity ON breach_incidents (severity);
CREATE INDEX IF NOT EXISTS idx_status ON breach_incidents (status);

-- Table: compliance_indicators
CREATE TABLE IF NOT EXISTS compliance_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    business_unit VARCHAR(100) NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    total_incidents INTEGER DEFAULT 0,
    critical_incidents INTEGER DEFAULT 0,
    avg_response_time_hours DECIMAL(10,2),
    pdpc_notifications_count INTEGER DEFAULT 0,
    compliance_score INTEGER,
    data_protection_maturity VARCHAR(20),
    trend_vs_previous_period VARCHAR(20),
    calculated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE (business_unit, period_start, period_end)
);

-- Table: dpo_guidance
CREATE TABLE IF NOT EXISTS dpo_guidance (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID REFERENCES breach_incidents(id),
    guidance_date DATE NOT NULL,
    guidance_type VARCHAR(50),
    guidance_text TEXT NOT NULL,
    issued_by VARCHAR(100),
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Reference constants (for app validation)
-- breach_types: Unauthorized Access, Data Loss, Ransomware/Malware, Phishing Attack, Insider Threat,
--               Third-Party/Vendor Breach, Misconfiguration, Physical Theft/Loss, Accidental Disclosure,
--               System Vulnerability, Other
-- root_causes: Phishing/Social Engineering, Weak Passwords/Authentication, Misconfigured Systems,
--              Unpatched Software, Inadequate Access Controls, Third-Party/Vendor Error,
--              Human Error/Negligence, Malicious Insider, Physical Security Failure, Unknown/Under Investigation
-- data_types: Personally Identifiable Information (PII), Financial Data, Health/Medical Records,
--             Academic Records, Employment Data, Authentication Credentials, Contact Information,
--             Biometric Data, Other Sensitive Data
-- business_units: School of Computing, School of Business, School of Engineering, School of Health Sciences,
--                 Administration, Finance, Human Resources, IT Services, Student Services, Research & Development
