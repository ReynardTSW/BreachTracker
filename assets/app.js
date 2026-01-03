// BreachTracker single-page app logic
(() => {
  const STORAGE_KEY = 'breach-tracker-state-v1';

  const BREACH_TYPES = [
    'Unauthorized Access',
    'Data Loss',
    'Ransomware/Malware',
    'Phishing Attack',
    'Insider Threat',
    'Third-Party/Vendor Breach',
    'Misconfiguration',
    'Physical Theft/Loss',
    'Accidental Disclosure',
    'System Vulnerability',
    'Other'
  ];

  const ROOT_CAUSES = [
    'Phishing/Social Engineering',
    'Weak Passwords/Authentication',
    'Misconfigured Systems',
    'Unpatched Software',
    'Inadequate Access Controls',
    'Third-Party/Vendor Error',
    'Human Error/Negligence',
    'Malicious Insider',
    'Physical Security Failure',
    'Unknown/Under Investigation'
  ];

  const DATA_TYPES = [
    'Personally Identifiable Information (PII)',
    'Financial Data',
    'Health/Medical Records',
    'Academic Records',
    'Employment Data',
    'Authentication Credentials',
    'Contact Information',
    'Biometric Data',
    'Other Sensitive Data'
  ];

  const BUSINESS_UNITS = [
    'School of Computing',
    'School of Business',
    'School of Engineering',
    'School of Health Sciences',
    'Administration',
    'Finance',
    'Human Resources',
    'IT Services',
    'Student Services',
    'Research & Development'
  ];

  const SEVERITY_COLORS = {
    CRITICAL: '#f87171',
    HIGH: '#fb923c',
    MEDIUM: '#facc15',
    LOW: '#86efac'
  };

  const STATUS_ORDER = ['DRAFT','DETECTED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'];

  const TRIGGER_KEYWORDS = {
    'Phishing': ['phishing', 'spoof', 'domain', 'email'],
    'Misconfig': ['misconfig', 'open bucket', 'public access', 'exposed', 's3'],
    'Access Control': ['unauthorized', 'access', 'privilege', 'credential'],
    'Patch Gap': ['unpatched', 'vulnerability', 'cve', 'patch'],
    'Human Error': ['accidental', 'mistake', 'wrong', 'mis-sent', 'typo'],
    'Vendor': ['vendor', 'third-party', 'supplier']
  };

  const ACTION_KEYWORDS = {
    'Reset Credentials': ['reset password', 'reset credentials', 'lock account'],
    'Block/Filter': ['block domain', 'block', 'filter', 'blacklist'],
    'Patch/Fix': ['patch', 'fixed', 'update', 'upgrade'],
    'Awareness/Training': ['train', 'awareness', 'education', 'simulate'],
    'DLP/Controls': ['dlp', 'rule', 'control', 'mfa', '2fa'],
    'Review/Policy': ['policy', 'review', 'procedure', 'checklist']
  };

  const VULNERABILITY_CLASSES = [
    {
      key: 'PHISHING',
      label: 'Phishing / Social Engineering',
      matcher: (incident, blob) => incident.breach_type === 'Phishing Attack' || (incident.root_cause || '').includes('Phishing') || blob.includes('phish') || blob.includes('spoof')
    },
    {
      key: 'MISCONFIG',
      label: 'Access Misconfigurations & Exposure',
      matcher: (incident, blob) => incident.breach_type === 'Misconfiguration' || (incident.root_cause || '').includes('Misconfigured') || blob.includes('misconfig') || blob.includes('open bucket') || blob.includes('public access') || blob.includes('exposed')
    },
    {
      key: 'ACCESS',
      label: 'Access Control / Credential Misuse',
      matcher: (incident, blob) => incident.breach_type === 'Unauthorized Access' || (incident.root_cause || '').includes('Access') || (incident.root_cause || '').includes('Weak Password') || blob.includes('unauthorized') || blob.includes('privilege') || blob.includes('credential')
    },
    {
      key: 'PATCH',
      label: 'Patch & Vulnerability Management',
      matcher: (incident, blob) => (incident.root_cause || '').includes('Unpatched') || incident.breach_type === 'System Vulnerability' || incident.breach_type === 'Ransomware/Malware' || blob.includes('cve') || blob.includes('patch')
    },
    {
      key: 'HUMAN',
      label: 'Human Error / Data Handling',
      matcher: (incident, blob) => incident.breach_type === 'Accidental Disclosure' || (incident.root_cause || '').includes('Human Error') || blob.includes('mis-sent') || blob.includes('typo') || blob.includes('sent to wrong')
    },
    {
      key: 'VENDOR',
      label: 'Third-Party / Vendor',
      matcher: (incident, blob) => incident.breach_type === 'Third-Party/Vendor Breach' || (incident.root_cause || '').includes('Vendor') || blob.includes('vendor') || blob.includes('third-party')
    },
    { key: 'OTHER', label: 'Other / Unknown', matcher: () => true }
  ];

  const SQL_SAMPLE_QUERIES = [
    {
      id: 'coverage',
      title: 'PDPC coverage by business unit',
      label: 'Coverage',
      sql: `SELECT business_unit AS unit,
                   COUNT(*) AS incidents,
                   SUM(CASE WHEN pdpc_required THEN 1 ELSE 0 END) AS pdpc_required,
                   SUM(CASE WHEN pdpc_notified THEN 1 ELSE 0 END) AS pdpc_notified,
                   ROUND(AVG(response_time_hours), 2) AS avg_response_hours
            FROM ?
            GROUP BY business_unit
            ORDER BY incidents DESC;`
    },
    {
      id: 'throughput',
      title: 'Response throughput by severity',
      label: 'Throughput',
      sql: `SELECT severity,
                   COUNT(*) AS incidents,
                   SUM(CASE WHEN status <> 'RESOLVED' THEN 1 ELSE 0 END) AS open_cases,
                   ROUND(AVG(response_time_hours), 2) AS avg_response_hours
            FROM ?
            GROUP BY severity
            ORDER BY incidents DESC;`
    },
    {
      id: 'auditTrail',
      title: 'Audit trail snapshot',
      label: 'Audit Trail',
      sql: `SELECT incident_id,
                   breach_type,
                   root_cause,
                   status,
                   pdpc_required,
                   pdpc_notified,
                   dpo_guidance,
                   response_time_hours,
                   discovered_date,
                   resolved_date
            FROM ?
            ORDER BY discovered_date DESC;`
    }
  ];

  const nowIso = () => new Date().toISOString();
  const uid = () => (crypto.randomUUID ? crypto.randomUUID() : `id-${Math.random().toString(16).slice(2)}`);


  const seedIncidents = [
    {
      id: uid(),
      incident_id: 'INC-2025-001',
      incident_date: '2025-12-05',
      discovered_date: '2025-12-05',
      reported_date: '2025-12-06',
      resolved_date: null,
      breach_type: 'Phishing Attack',
      severity: 'HIGH',
      root_cause: 'Phishing/Social Engineering',
      affected_records: 45,
      data_types: ['Authentication Credentials', 'Contact Information'],
      business_unit: 'IT Services',
      response_time_hours: null,
      status: 'INVESTIGATING',
      description: 'Employee credentials exposed via phishing email impersonating VDI team.',
      remediation_actions: 'Reset affected credentials, blocked sender domain, tightened MFA prompts.',
      lessons_learned: 'Need stronger phishing simulations and targeted MFA reminders.',
      pdpc_notification_required: true,
      pdpc_notified: false,
      dpo_guidance_issued: true,
      created_at: nowIso(),
      updated_at: nowIso(),
      created_by: 'Jane DPO',
      attachments: ['phishing_email_screenshot.png', 'affected_users.csv'],
      timeline: [
        { date: '2025-12-05', text: 'Phishing email reported by staff' },
        { date: '2025-12-06', text: 'Credentials reset for affected accounts' },
        { date: '2025-12-07', text: 'Domain blocked, SOC monitoring' }
      ],
      activities: [
        { date: '2025-12-06', text: 'Issued remediation action' },
        { date: '2025-12-07', text: 'MFA prompt hardening scheduled' }
      ],
      notes: [{ date: '2025-12-07', text: 'Awaiting updated user list from HR.' }]
    },
    {
      id: uid(),
      incident_id: 'INC-2025-002',
      incident_date: '2025-12-10',
      discovered_date: '2025-12-10',
      reported_date: '2025-12-11',
      resolved_date: null,
      breach_type: 'Misconfiguration',
      severity: 'CRITICAL',
      root_cause: 'Misconfigured Systems',
      affected_records: 1250,
      data_types: ['Personally Identifiable Information (PII)', 'Financial Data'],
      business_unit: 'School of Business',
      response_time_hours: null,
      status: 'CONTAINED',
      description: 'S3 bucket exposed student PII and payment records publicly.',
      remediation_actions: 'Closed public access, rotated keys, enabled object-lock, notified impacted parties.',
      lessons_learned: 'Automate configuration scanning pre-deployment.',
      pdpc_notification_required: true,
      pdpc_notified: true,
      dpo_guidance_issued: true,
      created_at: nowIso(),
      updated_at: nowIso(),
      created_by: 'Arun Compliance',
      attachments: ['s3-audit.txt', 'exposure_report.pdf'],
      timeline: [
        { date: '2025-12-10', text: 'Exposure detected by cloud config scan' },
        { date: '2025-12-10', text: 'Bucket access restricted and keys rotated' },
        { date: '2025-12-11', text: 'PDPC notification submitted' }
      ],
      activities: [
        { date: '2025-12-11', text: 'Ran follow-up scan: no additional exposures' },
        { date: '2025-12-12', text: 'Planned training for cloud admins' }
      ],
      notes: [{ date: '2025-12-12', text: 'Need pen-test validation before closing.' }]
    },
    {
      id: uid(),
      incident_id: 'INC-2025-003',
      incident_date: '2025-12-08',
      discovered_date: '2025-12-08',
      reported_date: null,
      resolved_date: '2025-12-10',
      breach_type: 'Accidental Disclosure',
      severity: 'MEDIUM',
      root_cause: 'Human Error/Negligence',
      affected_records: 12,
      data_types: ['Employment Data', 'Contact Information'],
      business_unit: 'Administration',
      response_time_hours: null,
      status: 'RESOLVED',
      description: 'Email sent to wrong recipient with salary data for 12 staff.',
      remediation_actions: 'Issued recall, notified intended recipients, updated mailing safeguards.',
      lessons_learned: 'Enable DLP rule for salary spreadsheets.',
      pdpc_notification_required: false,
      pdpc_notified: false,
      dpo_guidance_issued: false,
      created_at: nowIso(),
      updated_at: nowIso(),
      created_by: 'Lee Ops',
      attachments: ['email_recall.log'],
      timeline: [
        { date: '2025-12-08', text: 'Incident reported by recipient' },
        { date: '2025-12-09', text: 'DLP rule added for salary pattern' }
      ],
      activities: [
        { date: '2025-12-10', text: 'Remediated: verified recall success' }
      ],
      notes: []
    },
    {
      id: uid(),
      incident_id: 'INC-2025-004',
      incident_date: '2025-11-29',
      discovered_date: '2025-11-30',
      reported_date: '2025-12-01',
      resolved_date: null,
      breach_type: 'Ransomware/Malware',
      severity: 'CRITICAL',
      root_cause: 'Unpatched Software',
      affected_records: 4200,
      data_types: ['Health/Medical Records', 'Authentication Credentials'],
      business_unit: 'School of Computing',
      response_time_hours: null,
      status: 'CONTAINED',
      description: 'Ransomware encrypted lab file server; backups available.',
      remediation_actions: 'Isolated host, restored from backups, patched vulnerable service.',
      lessons_learned: 'Quarterly patch compliance checks needed.',
      pdpc_notification_required: true,
      pdpc_notified: true,
      dpo_guidance_issued: true,
      created_at: nowIso(),
      updated_at: nowIso(),
      created_by: 'SOC Lead',
      attachments: ['forensic_notes.pdf'],
      timeline: [
        { date: '2025-11-30', text: 'Host isolated, backups verified' },
        { date: '2025-12-01', text: 'PDPC notified' },
        { date: '2025-12-02', text: 'Restoration and patch completed' }
      ],
      activities: [
        { date: '2025-12-03', text: 'Post-incident review scheduled' }
      ],
      notes: []
    },
    {
      id: uid(),
      incident_id: 'INC-2025-005',
      incident_date: '2025-12-15',
      discovered_date: '2025-12-15',
      reported_date: null,
      resolved_date: null,
      breach_type: 'Third-Party/Vendor Breach',
      severity: 'HIGH',
      root_cause: 'Third-Party/Vendor Error',
      affected_records: 280,
      data_types: ['Personally Identifiable Information (PII)', 'Employment Data'],
      business_unit: 'Research & Development',
      response_time_hours: null,
      status: 'DETECTED',
      description: 'Vendor exposed research participant list via mis-sent email.',
      remediation_actions: 'Requested vendor purge, audit of distribution lists, added NDA reminder.',
      lessons_learned: 'Vendor governance checklist needed for mailouts.',
      pdpc_notification_required: true,
      pdpc_notified: false,
      dpo_guidance_issued: false,
      created_at: nowIso(),
      updated_at: nowIso(),
      created_by: 'DPO Desk',
      attachments: ['vendor_letter.docx'],
      timeline: [
        { date: '2025-12-15', text: 'Vendor notified and acknowledged' }
      ],
      activities: [
        { date: '2025-12-15', text: 'Awaiting vendor confirmation of purge' }
      ],
      notes: []
    },
    {
      id: uid(),
      incident_id: 'INC-2025-006',
      incident_date: '2025-10-20',
      discovered_date: '2025-10-21',
      reported_date: null,
      resolved_date: '2025-10-24',
      breach_type: 'Unauthorized Access',
      severity: 'MEDIUM',
      root_cause: 'Weak Passwords/Authentication',
      affected_records: 88,
      data_types: ['Academic Records', 'Contact Information'],
      business_unit: 'Student Services',
      response_time_hours: null,
      status: 'RESOLVED',
      description: 'Unauthorized access to student portal via reused passwords.',
      remediation_actions: 'Forced password reset, enabled MFA, ran awareness campaign.',
      lessons_learned: 'Password rotation alerts quarterly.',
      pdpc_notification_required: false,
      pdpc_notified: false,
      dpo_guidance_issued: true,
      created_at: nowIso(),
      updated_at: nowIso(),
      created_by: 'Security Ops',
      attachments: [],
      timeline: [
        { date: '2025-10-21', text: 'Credentials reset and MFA enabled' },
        { date: '2025-10-24', text: 'Closed after verification' }
      ],
      activities: [
        { date: '2025-10-25', text: 'Published MFA job-aid' }
      ],
      notes: []
    }
  ];

  const defaultState = {
    incidents: seedIncidents,
    drafts: [],
    business_units: BUSINESS_UNITS,
    filters: {
      severity: 'ALL',
      unit: 'ALL',
      status: 'ALL',
      search: ''
    }
  };

  const parseDate = (d) => new Date(d + 'T00:00:00');
  const formatDate = (d) => new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }).format(parseDate(d));
  const formatTime = (d) => new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(d));
  const daysBetween = (start, end) => Math.max(0, Math.round((parseDate(end) - parseDate(start)) / (1000 * 60 * 60 * 24)));
  const hoursBetween = (start, end) => Math.max(0, Math.round((parseDate(end) - parseDate(start)) / (1000 * 60 * 60)));

  const severityFromInputs = (records, dataTypes) => {
    const hasFinancial = dataTypes.some((d) => d.includes('Financial') || d.includes('Health'));
    if (records >= 1000 || hasFinancial) return 'CRITICAL';
    if (records >= 100 || dataTypes.includes('Authentication Credentials')) return 'HIGH';
    if (records >= 10) return 'MEDIUM';
    return 'LOW';
  };


  const ensureStateShape = (state) => ({
    incidents: Array.isArray(state.incidents) ? state.incidents : [],
    drafts: Array.isArray(state.drafts) ? state.drafts : [],
    business_units: Array.isArray(state.business_units) && state.business_units.length ? state.business_units : BUSINESS_UNITS,
    history: [],
    filters: state.filters || { severity: 'ALL', unit: 'ALL', status: 'ALL', search: '' }
  });

  const statusColor = (status) => {
    switch (status) {
      case 'DETECTED':
        return '#facc15';
      case 'INVESTIGATING':
        return '#fb923c';
      case 'CONTAINED':
        return '#60a5fa';
      case 'RESOLVED':
        return '#86efac';
      case 'DRAFT':
        return '#9fb1d0';
      default:
        return '#e5e7eb';
    }
  };

  const matchKeywords = (text, map) => {
    const lower = (text || '').toLowerCase();
    return Object.entries(map)
      .filter(([, keys]) => keys.some((k) => lower.includes(k)))
      .map(([k]) => k);
  };

  const deriveTags = (incident) => {
    const textBlob = [
      incident.description,
      incident.remediation_actions,
      incident.immediate_actions,
      incident.lessons_learned,
      incident.preventive_measures,
      incident.improvements,
      (incident.follow_up_actions || []).join(' ')
    ].join(' ').toLowerCase();
    return {
      triggers: matchKeywords(textBlob, TRIGGER_KEYWORDS),
      actions: matchKeywords(textBlob, ACTION_KEYWORDS)
    };
  };

  const aggregatePatterns = (incidents) => {
    const counts = { triggers: {}, actions: {} };
    const speed = {};
    incidents.forEach((i) => {
      const { triggers, actions } = deriveTags(i);
      const rt = i.response_time_hours;
      triggers.forEach((t) => {
        counts.triggers[t] = (counts.triggers[t] || 0) + 1;
        if (rt) {
          speed[t] = speed[t] || [];
          speed[t].push(rt);
        }
      });
      actions.forEach((a) => {
        counts.actions[a] = (counts.actions[a] || 0) + 1;
        if (rt) {
          speed[a] = speed[a] || [];
          speed[a].push(rt);
        }
      });
    });
    const top = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const avgSpeed = (k) => {
      if (!speed[k] || !speed[k].length) return null;
      const s = speed[k].reduce((a, v) => a + v, 0) / speed[k].length;
      return Number.isFinite(s) ? s : null;
    };
    const helpful = (type) => top(counts[type]).map(([k, v]) => ({ k, v, avg: avgSpeed(k) }));
    return {
      triggers: helpful('triggers'),
      actions: helpful('actions'),
      maxValue: Math.max(
        1,
        ...helpful('triggers').map((t) => t.v),
        ...helpful('actions').map((t) => t.v)
      )
    };
  };

  const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

  const classifyVulnerability = (incident) => {
    const blob = [
      incident.description,
      incident.remediation_actions,
      incident.immediate_actions,
      incident.lessons_learned,
      incident.preventive_measures,
      incident.improvements,
      (incident.follow_up_actions || []).join(' ')
    ].join(' ').toLowerCase();
    return VULNERABILITY_CLASSES.find((cls) => cls.matcher(incident, blob)) || VULNERABILITY_CLASSES[VULNERABILITY_CLASSES.length - 1];
  };

  const summarizeVulnerabilities = (incidents) => {
    const total = incidents.length || 1;
    const base = VULNERABILITY_CLASSES.reduce((acc, cls) => {
      acc[cls.key] = { ...cls, count: 0, open: 0, sample: null, topSeverity: 'LOW', frequency: 0 };
      return acc;
    }, {});
    incidents.forEach((inc) => {
      const cls = classifyVulnerability(inc);
      const entry = base[cls.key];
      entry.count += 1;
      entry.frequency = Number(((entry.count / total) * 100).toFixed(1));
      if (inc.status !== 'RESOLVED') entry.open += 1;
      const incomingRank = severityRank[inc.severity] || 0;
      const currentRank = severityRank[entry.topSeverity] || 0;
      if (incomingRank > currentRank) entry.topSeverity = inc.severity;
      if (!entry.sample) entry.sample = `${inc.incident_id} (${inc.breach_type})`;
    });
    return {
      total,
      items: Object.values(base)
        .sort((a, b) => (b.count - a.count) || ((severityRank[b.topSeverity] || 0) - (severityRank[a.topSeverity] || 0)))
    };
  };

  const buildSqlDataset = (incidents) => incidents.map((i) => ({
    response_time_hours: (() => {
      const parsed = Number(i.response_time_hours);
      return Number.isFinite(parsed) ? parsed : 0;
    })(),
    incident_id: i.incident_id,
    business_unit: i.business_unit,
    breach_type: i.breach_type,
    root_cause: i.root_cause,
    severity: i.severity,
    status: i.status,
    pdpc_required: !!i.pdpc_notification_required,
    pdpc_notified: !!i.pdpc_notified,
    dpo_guidance: !!i.dpo_guidance_issued,
    discovered_date: i.discovered_date,
    resolved_date: i.resolved_date || null,
    affected_records: Number(i.affected_records) || 0
  }));

  const groupBy = (rows, key) => rows.reduce((acc, row) => {
    const k = row[key] ?? 'Unknown';
    acc[k] = acc[k] || [];
    acc[k].push(row);
    return acc;
  }, {});

  const fallbackSqlResults = (sampleId, dataset) => {
    if (sampleId === 'coverage') {
      const grouped = groupBy(dataset, 'business_unit');
      return Object.entries(grouped).map(([unit, rows]) => {
        const avg = rows.length ? rows.reduce((acc, r) => acc + (Number(r.response_time_hours) || 0), 0) / rows.length : 0;
        return {
          unit,
          incidents: rows.length,
          pdpc_required: rows.filter((r) => r.pdpc_required).length,
          pdpc_notified: rows.filter((r) => r.pdpc_notified).length,
          avg_response_hours: Number.isFinite(avg) ? Number(avg.toFixed(2)) : null
        };
      }).sort((a, b) => b.incidents - a.incidents);
    }
    if (sampleId === 'throughput') {
      const grouped = groupBy(dataset, 'severity');
      return Object.entries(grouped).map(([severity, rows]) => {
        const avg = rows.length ? rows.reduce((acc, r) => acc + (Number(r.response_time_hours) || 0), 0) / rows.length : 0;
        return {
          severity,
          incidents: rows.length,
          open_cases: rows.filter((r) => r.status !== 'RESOLVED').length,
          avg_response_hours: Number.isFinite(avg) ? Number(avg.toFixed(2)) : null
        };
      }).sort((a, b) => b.incidents - a.incidents);
    }
    if (sampleId === 'auditTrail') {
      return [...dataset].sort((a, b) => (b.discovered_date || '').localeCompare(a.discovered_date || '')).slice(0, 50);
    }
    return dataset.slice(0, 25);
  };

  const runSqlQuery = (query, dataset, sampleId) => {
    if (typeof alasql !== 'undefined') {
      try {
        const rows = alasql(query, [dataset]);
        return { rows, usedFallback: false, error: null };
      } catch (err) {
        console.warn('SQL query failed, using fallback', err);
        return { rows: fallbackSqlResults(sampleId, dataset), usedFallback: true, error: err.message };
      }
    }
    return { rows: fallbackSqlResults(sampleId, dataset), usedFallback: true, error: null };
  };

  const tableHtml = (rows) => {
    if (!rows || !rows.length) return '<div class="muted">No data returned.</div>';
    const headers = Object.keys(rows[0]);
    const formatVal = (val) => {
      if (typeof val === 'boolean') return val ? 'Yes' : 'No';
      if (val === null || val === undefined) return '';
      return val;
    };
    return `
      <div class="table-wrap">
        <table class="table compact">
          <thead><tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr></thead>
          <tbody>
            ${rows.map((row) => `<tr>${headers.map((h) => `<td>${formatVal(row[h])}</td>`).join('')}</tr>`).join('')}
          </tbody>
        </table>
      </div>
    `;
  };

  const buildAnalyticsSnapshot = (incidents) => {
    const dataset = buildSqlDataset(incidents);
    const runSample = (id) => {
      const sample = SQL_SAMPLE_QUERIES.find((q) => q.id === id);
      if (!sample) return [];
      const result = runSqlQuery(sample.sql, dataset, id);
      return result.rows || [];
    };
    return {
      coverage: runSample('coverage'),
      throughput: runSample('throughput'),
      auditTrail: runSample('auditTrail')
    };
  };

  class Store {
    constructor() {
      const saved = localStorage.getItem(STORAGE_KEY);
      try {
        this.state = saved ? JSON.parse(saved) : defaultState;
      } catch (err) {
        console.warn('Corrupt saved state, resetting', err);
        this.state = defaultState;
        localStorage.removeItem(STORAGE_KEY);
      }
      this.state = ensureStateShape(this.state);
      if (!this.state.incidents || !this.state.incidents.length) {
        this.state = ensureStateShape(defaultState);
      }
      this.state.incidents = this.state.incidents.map((i) => this.withResponseTime(i));
      this.persist();
    }

    persist() {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.state));
    }

    listUnits() {
      const fromData = [...new Set([...this.state.business_units, ...this.state.incidents.map((i) => i.business_unit), ...this.state.drafts.map((d) => d.business_unit)])];
      return fromData;
    }

    addBusinessUnit(name) {
      const trimmed = (name || '').trim();
      if (!trimmed) return;
      if (!this.state.business_units.includes(trimmed)) {
        this.state.business_units.push(trimmed);
        this.persist();
      }
    }

    renameBusinessUnit(oldName, newName) {
      const newTrim = (newName || '').trim();
      if (!oldName || !newTrim) return;
      this.state.business_units = this.state.business_units.map((u) => u === oldName ? newTrim : u);
      this.state.incidents = this.state.incidents.map((i) => i.business_unit === oldName ? { ...i, business_unit: newTrim } : i);
      this.state.drafts = this.state.drafts.map((d) => d.business_unit === oldName ? { ...d, business_unit: newTrim } : d);
      if (this.state.filters.unit === oldName) this.state.filters.unit = newTrim;
      this.persist();
    }

    removeBusinessUnit(name) {
      if (!name) return;
      this.state.business_units = this.state.business_units.filter((u) => u !== name);
      if (this.state.filters.unit === name) this.state.filters.unit = 'ALL';
      this.persist();
    }

    withResponseTime(incident) {
      const resolvedDate = incident.resolved_date || new Date().toISOString().slice(0, 10);
      return {
        ...incident,
        response_time_hours: incident.discovered_date && resolvedDate
          ? hoursBetween(incident.discovered_date, resolvedDate)
          : null
      };
    }

    listIncidents() {
      const riskFlag = (i) => (i.pdpc_notification_required || i.pdpc_status === 'UNDER_REVIEW') && (!i.pdpc_notified || !i.dpo_guidance_issued);
      return [...this.state.incidents]
        .sort((a, b) => parseDate(b.discovered_date) - parseDate(a.discovered_date))
        .sort((a, b) => (riskFlag(b) ? 1 : 0) - (riskFlag(a) ? 1 : 0));
    }

    filterIncidents() {
      const { severity, unit, status, search } = this.state.filters;
      return this.listIncidents().filter((inc) => {
        const matchesSeverity = severity === 'ALL' || inc.severity === severity;
        const matchesUnit = unit === 'ALL' || inc.business_unit === unit;
        const matchesStatus = status === 'ALL' || inc.status === status;
        const matchesSearch = !search || inc.incident_id.toLowerCase().includes(search.toLowerCase()) || inc.description.toLowerCase().includes(search.toLowerCase());
        return matchesSeverity && matchesUnit && matchesStatus && matchesSearch;
      });
    }

    setFilters(filters) {
      this.state.filters = { ...this.state.filters, ...filters };
      this.persist();
    }

    addIncident(payload, draft = false) {
      const newIncidentId = this.nextIncidentId();
      const incident = this.withResponseTime({
        id: uid(),
        incident_id: newIncidentId,
        incident_date: payload.incident_date,
        discovered_date: payload.discovered_date,
        reported_date: payload.reported_date || null,
        resolved_date: payload.resolved_date || null,
        breach_type: payload.breach_type,
        severity: payload.severity,
        root_cause: payload.root_cause,
        affected_records: Number(payload.affected_records),
        data_types: payload.data_types,
        business_unit: payload.business_unit,
        response_time_hours: null,
        status: draft ? 'DRAFT' : payload.status || 'INVESTIGATING',
        description: payload.description,
        remediation_actions: payload.remediation_actions || '',
        remediation_actions_list: payload.remediation_actions_list || (payload.remediation_actions ? [payload.remediation_actions] : []),
        lessons_learned: payload.lessons_learned || '',
        preventive_measures: payload.preventive_measures || '',
        improvements: payload.improvements || '',
        follow_up_actions: payload.follow_up_actions || [],
        detection_method: payload.detection_method || '',
        immediate_actions: payload.immediate_actions || '',
        pdpc_notification_required: payload.pdpc_notification_required || false,
        pdpc_review_person: payload.pdpc_review_person || '',
        pdpc_notified: payload.pdpc_notified || false,
        pdpc_notified_person: payload.pdpc_notified_person || '',
        dpo_guidance_issued: payload.dpo_guidance_issued || false,
        dpo_notified_person: payload.dpo_notified_person || '',
        created_at: nowIso(),
        updated_at: nowIso(),
        created_by: payload.created_by || 'DPO Desk',
        attachments: payload.attachments || [],
        timeline: payload.timeline || [],
        activities: payload.activities || [],
        notes: payload.notes || [],
        history: payload.history || [],
        compliance_history: payload.compliance_history || [],
        pdpc_status: payload.pdpc_status || (payload.pdpc_notification_required ? 'YES' : 'NO'),
        pdpc_notified_date: payload.pdpc_notified_date || null,
        dpo_notified_date: payload.dpo_notified_date || null
      });
      if (draft) {
        this.state.drafts.push(incident);
      } else {
        this.state.incidents.unshift(incident);
      }
      this.persist();
      return incident;
    }

    promoteDraft(id) {
      const draft = this.state.drafts.find((d) => d.id === id);
      if (!draft) return null;
      const incident = this.withResponseTime({ ...draft, status: 'INVESTIGATING', updated_at: nowIso() });
      this.state.drafts = this.state.drafts.filter((d) => d.id !== id);
      this.state.incidents.unshift(incident);
      this.persist();
      return incident;
    }

    discardDraft(id) {
      this.state.drafts = this.state.drafts.filter((d) => d.id !== id);
      this.persist();
    }

    listDrafts() {
      return [...this.state.drafts].sort((a, b) => parseDate(b.discovered_date) - parseDate(a.discovered_date));
    }

    nextIncidentId() {
      const nextNumber = this.state.incidents.length + this.state.drafts.length + 1;
      const padded = String(nextNumber).padStart(3, '0');
      return `INC-2025-${padded}`;
    }

    updateIncident(id, updates) {
      const updated = this.state.incidents.map((inc) => {
        if (inc.id !== id) return inc;
        const diffKeys = Object.keys(updates || {}).filter((k) => k !== 'updated_at' && k !== 'history' && JSON.stringify(inc[k]) !== JSON.stringify(updates[k]));
        const readable = (v) => {
          if (Array.isArray(v)) return `[${v.length} items]`;
          if (v && typeof v === 'object') return JSON.stringify(v);
          return v ?? 'null';
        };
        const historyEntry = diffKeys.length
          ? { date: nowIso(), text: diffKeys.map((k) => `${k}: ${readable(inc[k])} -> ${readable(updates[k])}`).join(' | ') }
          : null;
        const history = historyEntry ? [...(inc.history || []), historyEntry] : (inc.history || []);
        const merged = this.withResponseTime({ ...inc, ...updates, history, updated_at: nowIso() });
        return merged;
      });
      this.state.incidents = updated;
      this.persist();
    }

    addNote(id, note) {
      this.state.incidents = this.state.incidents.map((inc) => inc.id === id ? { ...inc, notes: [...inc.notes, { date: nowIso().slice(0, 10), text: note }] } : inc);
      this.persist();
    }

    addActivity(id, text) {
      this.state.incidents = this.state.incidents.map((inc) => inc.id === id ? { ...inc, activities: [...inc.activities, { date: nowIso().slice(0, 10), text }] } : inc);
      this.persist();
    }

    getIncident(id) {
      return this.state.incidents.find((inc) => inc.id === id);
    }

    reset() {
      this.state = ensureStateShape(defaultState);
      this.persist();
    }
  }

  const store = new Store();
  let currentDetailId = null;
  let newIncidentExtras = { attachments: [], timeline: [], activities: [] };
  let currentEditIncidentId = null;

  const normalizeAttachment = (a) => {
    if (!a) return null;
    if (typeof a === 'string') return { name: a, url: a.startsWith('http') ? a : null };
    return { name: a.name || 'Attachment', url: a.url || null };
  };

  
  
  function statCard(label, value, tone) {
    const colorMap = { danger: 'var(--danger)', success: 'var(--success)', accent: 'var(--accent)' };
    const color = colorMap[tone] || 'var(--text)';
    return `
      <div class="stat-card">
        <div class="stat-label">${label}</div>
        <div class="stat-value" style="color:${color}">${value}</div>
      </div>
    `;
  }


  function buildTrendSeries(incidents, months) {
    const base = months.reduce((acc, m) => ({ ...acc, [m.key]: { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 } }), {});
    incidents.forEach((i) => {
      const key = i.discovered_date.slice(0, 7);
      if (base[key]) {
        base[key].total += 1;
        base[key][i.severity] += 1;
      }
    });
    return months.map((m) => ({ month: m.label, ...base[m.key] }));
  }


  function renderTrendChart(series, months, container) {
    if (!container) return;
    const max = Math.max(...series.map((s) => s.total), 1);
    const colors = {
      total: '#7dd3fc',
      CRITICAL: '#f472b6',
      HIGH: '#facc15',
      MEDIUM: '#a5f3fc',
      LOW: '#cbd5e1'
    };
    const lines = ['total', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const width = 1000;
    const height = 240;
    const stepX = width / Math.max(series.length - 1, 1);
    const yPos = (value) => height - (value / max) * (height - 40) - 6;
    const buildPath = (key) => series.map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${idx * stepX} ${yPos(p[key] || 0)}`).join(' ');
    const buildDots = (key) => series.map((p, idx) => `
      <circle cx="${idx * stepX}" cy="${yPos(p[key] || 0)}" r="4" fill="${colors[key]}" stroke="#0f1626" stroke-width="2" />
    `).join('');
    const gridLines = Array.from({ length: max }, (_, i) => i + 1).map((n) => {
      const y = yPos(n);
      return `<line x1="0" y1="${y}" x2="${width}" y2="${y}" stroke="rgba(255,255,255,0.05)" stroke-width="1" />`;
    }).join('');
    container.innerHTML = `
      <svg viewBox="0 0 ${width} ${height + 30}" preserveAspectRatio="none" role="img" aria-label="Breach trends over last six months">
        <defs>
          <linearGradient id="trend-bg" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stop-color="rgba(255,255,255,0.06)"/>
            <stop offset="100%" stop-color="rgba(255,255,255,0)"/>
          </linearGradient>
        </defs>
        <rect x="0" y="0" width="${width}" height="${height + 10}" fill="url(#trend-bg)"/>
        ${gridLines}
        ${lines.map((k) => `
          <path d="${buildPath(k)}" fill="none" stroke="${colors[k]}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" />
          ${buildDots(k)}
        `).join('')}
        ${months.map((m, idx) => `<text x="${idx * stepX}" y="${height + 22}" fill="#9fb1d0" font-size="12" text-anchor="middle">${m.label}</text>`).join('')}
      </svg>`;
  }


  function buildRootCauseSlices(incidents, months) {
    const monthKeys = new Set(months.map((m) => m.key));
    const recent = incidents.filter((i) => monthKeys.has(i.discovered_date.slice(0, 7)));
    const pool = recent.length ? recent : incidents;
    const counts = pool.reduce((acc, inc) => {
      acc[inc.root_cause] = (acc[inc.root_cause] || 0) + 1;
      return acc;
    }, {});
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
    const palette = ['#7dd3fc', '#f472b6', '#facc15', '#a5b4fc', '#34d399'];
    const total = pool.length;
    const slices = sorted.map(([label, value], idx) => ({
      label,
      value,
      percent: total ? Math.round((value / total) * 100) : 0,
      color: palette[idx % palette.length]
    }));
    const remainder = total - slices.reduce((sum, s) => sum + s.value, 0);
    if (remainder > 0) {
      slices.push({ label: 'Other', value: remainder, percent: Math.round((remainder / total) * 100), color: '#9fb1d0' });
    }
    return { total, slices };
  }


  function renderPieChart(pie, container) {
    if (!container) return;
    if (!pie || !pie.total) {
      container.innerHTML = '<div class="muted">No incidents yet.</div>';
      return;
    }
    let cursor = 0;
    const stops = pie.slices.map((slice) => {
      const start = (cursor / pie.total) * 360;
      cursor += slice.value;
      const end = (cursor / pie.total) * 360;
      return `${slice.color} ${start}deg ${end}deg`;
    }).join(', ');
    container.innerHTML = `
      <div class="pie-shell">
        <div class="pie-chart" style="background: conic-gradient(${stops});"></div>
        <div class="pie-hole">
          <div class="pie-total">${pie.total}</div>
          <div class="pie-label">Incidents</div>
        </div>
      </div>
    `;
  }

  function renderBarChart(items, maxValue) {
    if (!items || !items.length) return '<div class="detail-subtle">No data yet.</div>';
    return `
      <div class="bar-chart">
        ${items.map((i) => `
          <div class="bar-row">
            <div class="bar-row-header">
              <div class="bar-label">${i.k || '-'}</div>
              <div class="bar-meta">${i.k || '-'} — ${i.v} incident${i.v === 1 ? '' : 's'}${i.avg ? ` • ${i.avg.toFixed(1)}h` : ''}</div>
            </div>
            <div class="bar-track">
              <div class="bar-fill" style="width:${Math.max(8, (i.v / maxValue) * 100)}%"></div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  }


  function buildHeatmapData(incidents, units = store.listUnits()) {
    const weights = { CRITICAL: 5, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const mapped = units.map((unit) => {
      const unitIncidents = incidents.filter((i) => i.business_unit === unit);
      if (!unitIncidents.length) return null;
      const score = unitIncidents.reduce((acc, i) => acc + (weights[i.severity] || 1) + (i.status !== 'RESOLVED' ? 1 : 0), 0);
      const topSeverity = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].find((sev) => unitIncidents.some((i) => i.severity === sev)) || 'LOW';
      const open = unitIncidents.filter((i) => i.status !== 'RESOLVED').length;
      return { unit, count: unitIncidents.length, score, open, topSeverity, mostRecent: unitIncidents[0] };
    }).filter(Boolean);
    const maxScore = Math.max(...mapped.map((u) => u.score), 1);
    return mapped.map((u) => ({ ...u, fill: Math.max(8, Math.round((u.score / maxScore) * 100)) }));
  }


  function buildHighRiskUnits(incidents, units = store.listUnits()) {
    return units.map((unit) => {
      const unitIncidents = incidents.filter((i) => i.business_unit === unit);
      const score = complianceScore(unitIncidents);
      const mostRecent = unitIncidents[0];
      return { unit, score, incidents: unitIncidents.length, mostRecent };
    }).filter((u) => u.score < 70).sort((a, b) => a.score - b.score);
  }


  function detailTextBlock(text) { return `<pre class="detail-pre">${text}</pre>`; }


const setActiveView = (viewId) => {
    document.querySelectorAll('.view').forEach((v) => v.classList.remove('active'));
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    const view = document.getElementById(viewId);
    if (view) view.classList.add('active');
    const activeTab = document.querySelector(`.tab[data-view="${viewId}"]`);
    if (activeTab) activeTab.classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  function getRecentMonths(count) {
    const months = [];
    const now = new Date();
    for (let i = count - 1; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
      months.push({ label: d.toLocaleString('en', { month: 'short' }), key: `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}` });
    }
    return months;
  }

  function renderDashboard() {
    const container = document.getElementById('dashboard-view');
    const incidents = store.listIncidents();
    const months = getRecentMonths(6);
    const last30 = incidents.filter((i) => daysBetween(i.discovered_date, new Date().toISOString().slice(0, 10)) <= 30);
    const criticalCount = last30.filter((i) => i.severity === 'CRITICAL').length;
    const avgResponse = (() => {
      const withTime = last30.filter((i) => i.response_time_hours);
      if (!withTime.length) return '-';
      const avg = withTime.reduce((acc, i) => acc + i.response_time_hours, 0) / withTime.length;
      return `${avg.toFixed(1)}h`;
    })();
    const resolvedPct = incidents.length ? Math.round((incidents.filter((i) => i.status === 'RESOLVED').length / incidents.length) * 100) : 0;
    const alerts = incidents.filter((i) => ['CRITICAL', 'HIGH'].includes(i.severity) && i.status !== 'RESOLVED').length;
    document.getElementById('alert-count').textContent = alerts;
    const trendSeries = buildTrendSeries(incidents, months);
    const rootCause = buildRootCauseSlices(incidents, months);
    const units = store.listUnits();
    const heatmapData = buildHeatmapData(incidents, units);
    const highRisk = buildHighRiskUnits(incidents, units);
    const trendLegend = [
      { label: 'Total', color: '#7dd3fc' },
      { label: 'Critical', color: '#f472b6' },
      { label: 'High', color: '#facc15' },
      { label: 'Medium', color: '#a5f3fc' },
      { label: 'Low', color: '#cbd5e1' }
    ];

    container.innerHTML = `
      <div class="panel kpi-panel">
        <div class="panel-header">
          <div class="panel-title">Overview <span class="small">(Last 30 Days)</span></div>
        </div>
        <div class="kpi-grid">
          <div class="kpi-card">
            <div class="kpi-label">Incidents</div>
            <div class="kpi-value">${last30.length}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Critical</div>
            <div class="kpi-value danger-text">${criticalCount}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Avg Response</div>
            <div class="kpi-value accent-text">${avgResponse}</div>
          </div>
          <div class="kpi-card">
            <div class="kpi-label">Resolved</div>
            <div class="kpi-value success-text">${resolvedPct}%</div>
          </div>
        </div>
      </div>

      <div class="panel chart-panel">
        <div class="panel-header">
          <div class="panel-title">Breach Trends <span class="small">Last 6 months</span></div>
          <div class="chart-legend">
            ${trendLegend.map((item) => `<span class="legend-item"><span class="legend-dot" style="background:${item.color}"></span>${item.label}</span>`).join('')}
          </div>
        </div>
        <div id="trend-chart" class="chart trend-chart"></div>
      </div>

      <div class="grid analytics-split">
        <div class="panel">
          <div class="panel-title">Root Cause Analysis</div>
          <div class="root-cause">
            <div id="root-cause-chart" class="pie-container"></div>
            <div class="legend-column">
              ${rootCause.slices.length ? rootCause.slices.map((slice) => `
                <div class="legend-item">
                  <span class="legend-dot" style="background:${slice.color}"></span>
                  <span>${slice.label} ${slice.percent}%</span>
                </div>
              `).join('') : '<div class="muted">No incidents yet.</div>'}
            </div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-title">Business Unit Risk Heatmap</div>
          <div class="heatmap">
            ${heatmapData.length ? heatmapData.map((h) => `
              <div class="heatbar">
                <div>
                  <div class="heat-unit">${h.unit}</div>
                  <div class="heat-count">${h.count} incident${h.count === 1 ? '' : 's'}</div>
                </div>
                <div class="bar">
                  <div class="fill" style="width:${h.fill}%;"><span class="bar-label">${h.count} incident${h.count === 1 ? '' : 's'}</span></div>
                </div>
              </div>
            `).join('') : '<div class="muted">No incidents yet.</div>'}
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">High-Risk Units <span class="small">(Compliance Score < 70)</span></div>
          <a class="link" id="view-all-incidents">View All Incidents</a>
        </div>
        <div class="table-wrap">
          <table class="table compact">
            <thead>
              <tr><th>Business Unit</th><th>Score</th><th>Incidents</th><th>Status</th></tr>
            </thead>
            <tbody>
              ${highRisk.length ? highRisk.map((u) => `
                <tr>
                  <td>${u.unit}</td>
                  <td><span class="badge">${u.score}</span></td>
                  <td>${u.incidents}</td>
                  <td>${u.mostRecent ? `<span class="chip status ${u.mostRecent.status.toLowerCase()}">${u.mostRecent.status}</span>` : '<span class="muted">No incidents</span>'}</td>
                </tr>
              `).join('') : '<tr><td colspan="4" class="muted">No units under 70 right now.</td></tr>'}
            </tbody>
          </table>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">Pattern Signals</div>
        <div class="grid grid-2">
          <div class="pattern-chart">
            <div class="mini-title">Top Triggers</div>
            ${renderBarChart(aggregatePatterns(incidents).triggers, aggregatePatterns(incidents).maxValue)}
          </div>
          <div class="pattern-chart">
            <div class="mini-title">Top Actions</div>
            ${renderBarChart(aggregatePatterns(incidents).actions, aggregatePatterns(incidents).maxValue)}
          </div>
        </div>
      </div>
    `;

    renderTrendChart(trendSeries, months, document.getElementById('trend-chart'));
    renderPieChart(rootCause, document.getElementById('root-cause-chart'));

    const viewAll = document.getElementById('view-all-incidents');
    if (viewAll) {
      viewAll.onclick = () => { setActiveView('registry-view'); renderRegistry(); };
    }
  }

  function renderRegistry() {
    const container = document.getElementById('registry-view');
    const incidents = store.filterIncidents();
    const filters = store.state.filters;
    const drafts = store.listDrafts();
    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Breach Incident Registry</div>
          <div class="actions">
            <button class="btn primary" id="log-new">+ Log New Incident</button>
            <button class="btn ghost" id="view-drafts">Drafts (${drafts.length})</button>
          </div>
        </div>
        <div class="filters">
          <select id="filter-severity" class="filter">
            <option value="ALL">All Severities</option>
            ${['CRITICAL','HIGH','MEDIUM','LOW'].map((s) => `<option value="${s}" ${filters.severity===s?'selected':''}>${s}</option>`).join('')}
          </select>
          <select id="filter-unit" class="filter">
            <option value="ALL">All Units</option>
            ${BUSINESS_UNITS.map((u) => `<option value="${u}" ${filters.unit===u?'selected':''}>${u}</option>`).join('')}
          </select>
          <select id="filter-status" class="filter">
            <option value="ALL">All Status</option>
            ${STATUS_ORDER.map((s) => `<option value="${s}" ${filters.status===s?'selected':''}>${s}</option>`).join('')}
          </select>
          <input id="filter-search" class="filter" placeholder="Search" value="${filters.search||''}" />
        </div>
      </div>
      <div class="list" id="registry-list"></div>
    `;
    const list = document.getElementById('registry-list');
    if (!incidents.length) {
      list.innerHTML = '<div class="card">No incidents found.</div>';
    } else {
      list.innerHTML = incidents.map((inc) => {
        const pdpcRisk = (inc.pdpc_notification_required || inc.pdpc_status === 'UNDER_REVIEW') && (!inc.pdpc_notified || !inc.dpo_guidance_issued);
        return `
        <div class="card ${pdpcRisk ? 'pdpc-risk' : ''}">
          <div class="card-header">
            <div class="inline" style="gap:8px;">
              <span class="badge">${inc.incident_id}</span>
              <span class="chip status ${inc.severity.toLowerCase()}">${inc.severity}</span>
              <span class="chip status ${inc.status.toLowerCase()}">${inc.status}</span>
              <span class="pill">${inc.business_unit}</span>
              <span class="pill ghost">Notes: ${inc.notes?.length || 0}</span>
            </div>
            <div class="muted">${formatDate(inc.discovered_date)} - ${inc.affected_records} records</div>
          </div>
          <div class="small">${inc.description}</div>
          <div class="actions" style="margin-top:8px;">
            <button class="btn ghost" data-view-id="${inc.id}">View Details</button>
            <button class="btn ghost" data-note-id="${inc.id}">Add Note</button>
            <button class="btn ghost" data-followup-id="${inc.id}">Follow-up Actions</button>
            ${inc.status!=='RESOLVED' ? `<button class="btn primary" data-resolve-id="${inc.id}">Mark Resolved</button>`:''}
          </div>
        </div>`;
      }).join('');
    }
    document.getElementById('filter-severity').onchange = (e) => { store.setFilters({ severity:e.target.value }); renderRegistry(); };
    document.getElementById('filter-unit').onchange = (e) => { store.setFilters({ unit:e.target.value }); renderRegistry(); };
    document.getElementById('filter-status').onchange = (e) => { store.setFilters({ status:e.target.value }); renderRegistry(); };
    document.getElementById('filter-search').oninput = (e) => { store.setFilters({ search:e.target.value }); renderRegistry(); };
    document.getElementById('log-new').onclick = () => { setActiveView('new-incident-view'); renderNewIncidentForm(); };
    document.getElementById('view-drafts').onclick = () => {
      if (!drafts.length) {
        alert('No drafts available.');
        return;
      }
      // show latest draft
      renderDraftOverlay(drafts[0]);
    };
  }

  function renderDetailPlaceholder() {
    const container = document.getElementById('detail-view');
    container.innerHTML = `
      <div class="panel detail-shell">
        <div class="detail-section">
          <div class="detail-title">Incident Detail</div>
          <div class="detail-separator"></div>
          <div class="detail-list detail-subtle">Select an incident from the registry to view details.</div>
        </div>
      </div>
    `;
  }

  function renderIncidentDetail(id) {
    const incident = store.getIncident(id);
    currentDetailId = id;
    if (!incident) { renderDetailPlaceholder(); return; }
    const container = document.getElementById('detail-view');
    const renderList = (items) => items && items.length ? items.map((t) => `<div class="wire-item">${t}</div>`).join('') : '<div class="detail-subtle">No entries.</div>';
    const timeline = renderList((incident.timeline || []).map((t) => `${formatDate(t.date)} - ${t.text}`));
    const activities = renderList((incident.activities || []).map((a) => `${a.person ? `[${a.person}] ` : ''}${formatDate(a.date)} - ${a.text}`));
    const attachments = renderList((incident.attachments || []).map((raw) => {
      const a = normalizeAttachment(raw);
      return `<span class="muted">📎</span> ${a.name} <button class="btn ghost sm" data-open-attachment="${a.url || a.name}" ${a.url ? '' : 'data-has-url="false"'}>Open</button>`;
    }));
    container.innerHTML = `
      <div class="panel wire-detail detail-shell">
        <div class="wire-detail-header">
          <a class="link" id="back-to-registry"><- Back to Registry</a>
          <div class="inline" style="gap:10px;align-items:center;">
            <span class="badge">${incident.incident_id}</span>
            <span class="link" id="edit-detail">[Edit]</span>
          </div>
        </div>

        <div class="wire-detail-topline">
          <span class="dot ${incident.severity.toLowerCase()}"></span> ${incident.severity} |
          ${incident.business_unit} |
          ${incident.status}
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Incident Summary</div>
          <div class="detail-pre">
Incident ID: ${incident.incident_id}
Type: ${incident.breach_type}
Root Cause: ${incident.root_cause}
Incident Date: ${formatDate(incident.incident_date)}
Discovered: ${formatDate(incident.discovered_date)}${incident.incident_date === incident.discovered_date ? ' (same day)' : ''}
Response Time: ${incident.response_time_hours ? `${incident.response_time_hours} hours` : 'n/a'}

Impact: ${incident.affected_records} records compromised
Data Types: ${incident.data_types.join(', ')}
          </div>
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Description</div>
          ${detailTextBlock(incident.description)}
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Remediation Actions</div>
          <div class="wire-list">
            ${incident.remediation_actions_list && incident.remediation_actions_list.length
              ? incident.remediation_actions_list.map((r) => `<div class="wire-item">• ${r}</div>`).join('')
              : incident.remediation_actions
                ? `<div class="wire-item">• ${incident.remediation_actions}</div>`
                : '<div class="detail-subtle">No remediation captured.</div>'}
          </div>
          <div class="inline-form" id="remediation-inline-form">
            <input id="detail-remediation-text" placeholder="Add remediation action" />
            <button class="btn ghost sm" id="detail-add-remediation">Add</button>
          </div>
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Follow-up Actions</div>
          <div class="wire-list">
            ${incident.follow_up_actions && incident.follow_up_actions.length ? incident.follow_up_actions.map((f) => `<div class="wire-item">• ${f}</div>`).join('') : '<div class="detail-subtle">No follow-up actions captured.</div>'}
          </div>
          <div class="inline-form" id="followup-inline-form">
            <input id="detail-followup-text" placeholder="Add follow-up action" />
            <button class="btn ghost sm" id="detail-add-followup">Add</button>
          </div>
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Compliance Status</div>
          <div class="detail-pre">
PDPC Notification: ${incident.pdpc_notification_required ? 'Required' : 'Not Required'}
PDPC Status: ${incident.pdpc_status || (incident.pdpc_notification_required ? 'YES' : 'NO')} ${incident.pdpc_review_person ? `(${incident.pdpc_review_person})` : ''}
PDPC Notified: ${incident.pdpc_notified ? 'Yes' : 'No'} ${incident.pdpc_notified_date ? `(${formatDate(incident.pdpc_notified_date)})` : ''} ${incident.pdpc_notified_person ? `- ${incident.pdpc_notified_person}` : ''}
DPO Guidance Issued: ${incident.dpo_guidance_issued ? 'Yes' : 'No'} ${incident.dpo_notified_date ? `(${formatDate(incident.dpo_notified_date)})` : ''} ${incident.dpo_notified_person ? `- ${incident.dpo_notified_person}` : ''}
Guidance: ${incident.lessons_learned || 'Not documented.'}
Preventive Measures: ${incident.preventive_measures || 'Not documented.'}
Improvements: ${incident.improvements || 'Not documented.'}
          </div>
          <div class="compliance-controls">
            <div class="control-group">
              <label>Status</label>
              <select id="detail-pdpc-status" class="sm-input">
                <option value="YES" ${incident.pdpc_status==='YES'?'selected':''}>YES</option>
                <option value="NO" ${incident.pdpc_status==='NO'?'selected':''}>NO</option>
                <option value="UNDER_REVIEW" ${incident.pdpc_status==='UNDER_REVIEW'?'selected':''}>UNDER REVIEW</option>
              </select>
            </div>
            <div class="control-group">
              <label>Reviewer (for Under Review)</label>
              <input id="detail-review-person" class="sm-input" placeholder="Reviewer" value="${incident.pdpc_review_person || ''}" />
            </div>
            <div class="control-group">
              <label><input type="checkbox" id="detail-pdpc-notified" ${incident.pdpc_notified?'checked':''}/> PDPC Notified</label>
              <input id="detail-pdpc-person" class="sm-input" placeholder="PDPC contact" value="${incident.pdpc_notified_person || ''}" />
            </div>
            <div class="control-group">
              <label><input type="checkbox" id="detail-dpo-notified" ${incident.dpo_guidance_issued?'checked':''}/> DPO Notified</label>
              <input id="detail-dpo-person" class="sm-input" placeholder="DPO contact" value="${incident.dpo_notified_person || ''}" />
            </div>
            <div class="control-group">
              <button class="btn ghost" id="detail-update-compliance">Update</button>
            </div>
          </div>
          <div class="wire-list">
            <div class="wire-title">Compliance History</div>
            ${incident.compliance_history && incident.compliance_history.length
              ? incident.compliance_history.map((h) => `<div class="wire-item">${formatDate(h.date)} - ${h.text}</div>`).join('')
              : '<div class="detail-subtle">No compliance changes logged.</div>'}
          </div>
          <div class="wire-line"></div>
          <div class="wire-block">
            <div class="wire-title">Change History</div>
            <div class="wire-list">
              ${incident.history && incident.history.length
                ? incident.history.map((h) => `<div class="wire-item">${formatDate(h.date.slice(0,10))} ${h.date.slice(11,16)} - ${h.text}</div>`).join('')
                : '<div class="detail-subtle">No edits recorded yet.</div>'}
            </div>
          </div>
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Attachments (${(incident.attachments || []).length})</div>
          <div class="wire-list">
            ${attachments}
          </div>
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Timeline</div>
          <div class="wire-list">${timeline}</div>
          <div class="inline-form" id="timeline-inline-form">
            <input id="detail-timeline-dt" type="datetime-local" />
            <input id="detail-timeline-text" placeholder="Event detail" />
            <button class="btn ghost sm" id="detail-add-timeline">Add</button>
          </div>
        </div>

        <div class="wire-line"></div>

        <div class="wire-block">
          <div class="wire-title">Activity Log (${(incident.activities || []).length} entries)</div>
          <div class="wire-list">${activities}</div>
          <div class="inline-form" id="activity-inline-form">
            <input id="detail-activity-person" placeholder="Person" />
            <input id="detail-activity-dt" type="datetime-local" />
            <input id="detail-activity-text" placeholder="Activity detail" />
            <button class="btn ghost sm" id="detail-add-activity">Add</button>
          </div>
          <div class="detail-actions">
            <button class="btn ghost" id="add-note-detail">Add Note</button>
            ${incident.status !== 'RESOLVED' ? `<button class="btn primary" data-resolve-id="${incident.id}">Mark as Resolved</button>` : ''}
            <button class="btn ghost" id="export-single">Export to PDF</button>
            <button class="btn ghost" id="share-link">Share Link</button>
          </div>
          <div class="list" style="margin-top:8px;">
            ${incident.notes && incident.notes.length ? incident.notes.map((n) => `
              <div class="note"><strong>${formatDate(n.date)}</strong> — ${n.text}</div>
            `).join('') : '<div class="detail-subtle">No notes yet.</div>'}
          </div>
        </div>
      </div>
    `;
    document.getElementById('back-to-registry').onclick = () => { setActiveView('registry-view'); renderRegistry(); };
    const addDetail = document.getElementById('add-note-detail');
    if (addDetail) {
      addDetail.onclick = () => {
        const text = prompt('Add note');
        if (text) {
          store.addNote(id, text);
          renderIncidentDetail(id);
          renderRegistry();
        }
      };
    }
    const exportBtn = document.getElementById('export-single');
    if (exportBtn) exportBtn.onclick = () => exportIncident([incident], incident.incident_id.toLowerCase());
    const share = document.getElementById('share-link');
    if (share) share.onclick = () => navigator.clipboard?.writeText(location.href).then(() => alert('Link copied'), () => alert('Could not copy link.'));
    document.querySelectorAll('[data-open-attachment]').forEach((btn) => {
      btn.onclick = () => {
        const href = btn.dataset.openAttachment;
        const hasUrl = btn.dataset.hasUrl !== 'false';
        if (hasUrl && href && href.startsWith('http')) {
          window.open(href, '_blank');
        } else if (hasUrl && href && href.startsWith('blob:')) {
          window.open(href, '_blank');
        } else {
          alert('This attachment needs a URL to open. Please provide a link when adding.');
        }
      };
    });
    const addTimeline = document.getElementById('detail-add-timeline');
    if (addTimeline) {
      addTimeline.onclick = () => {
        const dt = document.getElementById('detail-timeline-dt').value;
        const text = document.getElementById('detail-timeline-text').value;
        if (dt && text.trim()) {
          store.updateIncident(id, {
            timeline: [...(incident.timeline || []), { date: dt.slice(0, 10), text: `${formatTime(dt)} - ${text.trim()}` }]
          });
          renderIncidentDetail(id);
        }
      };
    }
    const addRemediation = document.getElementById('detail-add-remediation');
    if (addRemediation) {
      addRemediation.onclick = () => {
        const text = document.getElementById('detail-remediation-text').value;
        if (text.trim()) {
          store.updateIncident(id, { remediation_actions_list: [...(incident.remediation_actions_list || []), text.trim()] });
          renderIncidentDetail(id);
        }
      };
    }
    const addActivity = document.getElementById('detail-add-activity');
    if (addActivity) {
      addActivity.onclick = () => {
        const dt = document.getElementById('detail-activity-dt').value;
        const text = document.getElementById('detail-activity-text').value;
        const person = document.getElementById('detail-activity-person').value;
        if (dt && text.trim()) {
          store.updateIncident(id, {
            activities: [...(incident.activities || []), { date: dt.slice(0, 10), text: `${formatTime(dt)} - ${text.trim()}`, person: person || '' }]
          });
          renderIncidentDetail(id);
        }
      };
    }
    const addFollow = document.getElementById('detail-add-followup');
    if (addFollow) {
      addFollow.onclick = () => {
        const text = document.getElementById('detail-followup-text').value;
        if (text.trim()) {
          store.updateIncident(id, { follow_up_actions: [...(incident.follow_up_actions || []), text.trim()] });
          renderIncidentDetail(id);
        }
      };
    }
    const updateCompliance = document.getElementById('detail-update-compliance');
    if (updateCompliance) {
      updateCompliance.onclick = () => {
        const statusVal = document.getElementById('detail-pdpc-status').value;
        const reviewPerson = document.getElementById('detail-review-person').value.trim();
        const pdpcNot = document.getElementById('detail-pdpc-notified').checked;
        const pdpcPerson = document.getElementById('detail-pdpc-person').value.trim();
        const dpoNot = document.getElementById('detail-dpo-notified').checked;
        const dpoPerson = document.getElementById('detail-dpo-person').value.trim();
        if (statusVal === 'UNDER_REVIEW' && !reviewPerson) { alert('Reviewer required for UNDER REVIEW.'); return; }
        if (pdpcNot && !pdpcPerson) { alert('PDPC contact required when notified.'); return; }
        if (dpoNot && !dpoPerson) { alert('DPO contact required when notified.'); return; }
        const historyEntry = `${statusVal} | PDPC Notified: ${pdpcNot ? 'Yes' : 'No'}${pdpcPerson ? ` (${pdpcPerson})` : ''} | DPO Notified: ${dpoNot ? 'Yes' : 'No'}${dpoPerson ? ` (${dpoPerson})` : ''}`;
        store.updateIncident(id, {
          pdpc_status: statusVal,
          pdpc_review_person: reviewPerson,
          pdpc_notified: pdpcNot,
          pdpc_notified_person: pdpcPerson,
          dpo_guidance_issued: dpoNot,
          dpo_notified_person: dpoPerson,
          compliance_history: [...(incident.compliance_history || []), { date: new Date().toISOString().slice(0,10), text: historyEntry }]
        });
        renderIncidentDetail(id);
        renderDashboard();
        renderCompliance();
        renderRegistry();
      };
    }
    const editBtn = document.getElementById('edit-detail');
    if (editBtn) {
      editBtn.onclick = () => {
        currentEditIncidentId = id;
        newIncidentExtras = {
          attachments: [...(incident.attachments || [])],
          timeline: [...(incident.timeline || [])],
          activities: [...(incident.activities || [])]
        };
        setActiveView('new-incident-view');
        renderNewIncidentForm();
      };
    }
  }

  function renderDraftOverlay(draft) {
    if (!draft) return;
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <div class="modal-title">Draft Saved</div>
          <button class="btn ghost sm" id="close-draft-modal">Close</button>
        </div>
        <div class="modal-body">
          <div class="muted">INCIDENT DRAFT</div>
          <div class="modal-row"><strong>ID:</strong> ${draft.incident_id}</div>
          <div class="modal-row"><strong>Business Unit:</strong> ${draft.business_unit}</div>
          <div class="modal-row"><strong>Breach Type:</strong> ${draft.breach_type}</div>
          <div class="modal-row"><strong>Severity:</strong> ${draft.severity}</div>
          <div class="modal-row"><strong>Impact:</strong> ${draft.affected_records} records</div>
          <div class="modal-row"><strong>Description:</strong> ${draft.description || 'No description provided.'}</div>
        </div>
        <div class="modal-actions">
          <button class="btn ghost" id="discard-draft">Discard</button>
          <button class="btn primary" id="submit-draft">Submit Draft</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const cleanup = () => overlay.remove();
    overlay.querySelector('#close-draft-modal').onclick = cleanup;
    overlay.querySelector('#discard-draft').onclick = () => {
      store.discardDraft(draft.id);
      cleanup();
    };
    overlay.querySelector('#submit-draft').onclick = () => {
      const promoted = store.promoteDraft(draft.id);
      cleanup();
      if (promoted) {
        setActiveView('detail-view');
        renderIncidentDetail(promoted.id);
        renderRegistry();
        renderDashboard();
      }
    };
  }

  function renderUnitManager() {
    const units = store.listUnits();
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal">
        <div class="modal-header">
          <div class="modal-title">Manage Business Units</div>
          <button class="btn ghost sm" id="close-unit-modal">Close</button>
        </div>
        <div class="modal-body">
          <div class="modal-row">Existing Units:</div>
          <div class="wire-list" id="unit-list">
            ${units.map((u) => `
              <div class="inline" style="gap:8px;align-items:center;margin-bottom:6px;">
                <span>${u}</span>
                <button class="btn ghost sm" data-rename-unit="${u}">Rename</button>
                <button class="btn ghost sm" data-remove-unit="${u}">Remove</button>
              </div>
            `).join('')}
          </div>
          <div class="inline" style="gap:8px;align-items:center;margin-top:10px;">
            <input id="unit-new-name" class="sm-input" placeholder="Add new unit" />
            <button class="btn primary sm" id="unit-add-btn">Add</button>
          </div>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const cleanup = () => overlay.remove();
    overlay.querySelector('#close-unit-modal').onclick = cleanup;
    overlay.querySelector('#unit-add-btn').onclick = () => {
      const val = overlay.querySelector('#unit-new-name').value.trim();
      if (val) {
        store.addBusinessUnit(val);
        cleanup();
        renderNewIncidentForm();
      }
    };
    overlay.querySelectorAll('[data-rename-unit]').forEach((btn) => {
      btn.onclick = () => {
        const oldName = btn.dataset.renameUnit;
        const newName = prompt(`Rename "${oldName}" to:`, oldName);
        if (newName && newName.trim()) {
          store.renameBusinessUnit(oldName, newName.trim());
          cleanup();
          renderNewIncidentForm();
          renderDashboard();
          renderRegistry();
          renderCompliance();
        }
      };
    });
    overlay.querySelectorAll('[data-remove-unit]').forEach((btn) => {
      btn.onclick = () => {
        const name = btn.dataset.removeUnit;
        const confirmRemove = confirm(`Remove "${name}" from unit list? (Incidents will retain their unit value.)`);
        if (confirmRemove) {
          store.removeBusinessUnit(name);
          cleanup();
          renderNewIncidentForm();
          renderDashboard();
          renderRegistry();
          renderCompliance();
        }
      };
    });
  }

  function renderNewIncidentForm() {
    const today = new Date().toISOString().slice(0,10);
    const container = document.getElementById('new-incident-view');
    const extras = newIncidentExtras;
    const defaultDataTypes = DATA_TYPES.slice(0, 3);
    const units = store.listUnits();
    const existing = currentEditIncidentId ? store.getIncident(currentEditIncidentId) : null;
    const checkbox = (label, checked = false) => `
      <label class="checkbox">
        <input type="checkbox" name="data_type" value="${label}" ${checked ? 'checked' : ''} />
        <span>${label}</span>
      </label>
    `;

    container.innerHTML = `
      <div class="panel wireform">
        <div class="wireform-header">Log New Breach Incident <span class="badge">Next ID: ${store.nextIncidentId()}</span></div>

        <div class="wire-section">
          <div class="wire-title">Incident Details</div>
          <div class="wire-grid">
            <div class="form-group">
              <label>Incident Date *</label>
              <input id="incident_date" type="date" value="${existing ? existing.incident_date : today}" />
            </div>
            <div class="form-group">
              <label>Discovery Date *</label>
              <input id="discovered_date" type="date" value="${existing ? existing.discovered_date : today}" />
            </div>
            <div class="form-group">
              <label>Breach Type *</label>
              <select id="breach_type">${BREACH_TYPES.map((t)=>`<option ${existing && existing.breach_type===t?'selected':''}>${t}</option>`).join('')}</select>
            </div>
            <div class="form-group">
              <label>Root Cause *</label>
              <select id="root_cause">${ROOT_CAUSES.map((t)=>`<option ${existing && existing.root_cause===t?'selected':''}>${t}</option>`).join('')}</select>
            </div>
          <div class="form-group">
            <label>Business Unit Affected *</label>
            <select id="business_unit">${units.map((t)=>`<option ${existing && existing.business_unit===t?'selected':''}>${t}</option>`).join('')}</select>
            <div class="inline" style="gap:8px;margin-top:6px;">
              <input id="new_business_unit" class="sm-input" placeholder="Add new business unit" />
              <button class="btn ghost sm" id="add-business-unit">Add</button>
              <button class="btn ghost sm" id="manage-business-unit">Manage</button>
            </div>
          </div>
          </div>
        </div>

        <div class="wire-section">
          <div class="wire-title">Impact Assessment</div>
          <div class="wire-grid impact-grid">
            <div class="form-group">
              <label>Number of Records Affected *</label>
            <input id="affected_records" type="number" value="${existing ? existing.affected_records : 10}" class="big-input" />
            </div>
            <div class="form-group">
              <label>Types of Data Exposed *</label>
              <div class="checkbox-grid">
              ${DATA_TYPES.map((t) => checkbox(t, existing ? existing.data_types.includes(t) : defaultDataTypes.includes(t))).join('')}
              </div>
            </div>
            <div class="form-group">
              <label>Severity (auto-calculated)</label>
              <div id="severity-badge" class="severity-box">MEDIUM</div>
              <div id="severity-summary" class="severity-summary muted"></div>
            </div>
          </div>
        </div>

        <div class="wire-section">
          <div class="wire-title">Description</div>
          <div class="wire-grid triple">
            <div class="form-group">
              <label>What happened? *</label>
              <textarea id="description" placeholder="Describe the incident...">${existing ? existing.description : ''}</textarea>
            </div>
            <div class="form-group">
              <label>How was it discovered?</label>
              <textarea id="discovered_how" placeholder="Detection method..."></textarea>
            </div>
            <div class="form-group">
              <label>Immediate Actions</label>
              <textarea id="immediate_actions" placeholder="Containment steps..."></textarea>
            </div>
          </div>
        </div>

        <div class="wire-section">
          <div class="wire-title">Compliance</div>
          <div class="wire-grid">
            <div class="form-group">
              <label>PDPC Notification Required?</label>
              <div class="radio-row">
                <label class="radio"><input type="radio" name="pdpc_required" value="yes" checked /> Yes</label>
                <label class="radio"><input type="radio" name="pdpc_required" value="no" /> No</label>
                <label class="radio"><input type="radio" name="pdpc_required" value="review" /> Under Review</label>
              </div>
              <input id="pdpc_review_person" class="sm-input" placeholder="Reviewer name" style="display:none;margin-top:6px;" />
            </div>
            <div class="form-group">
              <label>PDPC Notified?</label>
              <div class="inline" style="gap:10px;align-items:center;">
                <label class="checkbox"><input type="checkbox" id="pdpc_notified" /> <span>Yes</span></label>
                <input id="pdpc_notified_date" type="date" class="sm-input" />
                <input id="pdpc_notified_person" class="sm-input" placeholder="Person notified" style="display:none;" />
              </div>
            </div>
            <div class="form-group">
              <label>DPO Notified?</label>
              <div class="inline" style="gap:10px;align-items:center;">
                <label class="checkbox"><input type="checkbox" id="dpo_notified" /> <span>Yes</span></label>
                <input id="dpo_notified_date" type="date" class="sm-input" />
                <input id="dpo_notified_person" class="sm-input" placeholder="Person notified" style="display:none;" />
              </div>
            </div>
          </div>
        </div>

        <div class="wire-section">
          <div class="wire-title">Attachments</div>
          <div class="wire-list" id="attachments-list"></div>
          <div class="inline-form">
            <input id="attachment_input" placeholder="Link or filename" />
            <input id="attachment_file" type="file" style="display:none;" />
            <button class="btn ghost sm" id="add-attachment">Add Attachment</button>
          </div>
        </div>

        <div class="wire-section">
          <div class="wire-title">Timeline</div>
          <div class="wire-list" id="timeline-list"></div>
          <div class="inline-form">
            <input id="timeline_dt" type="datetime-local" />
            <input id="timeline_text" placeholder="Event detail" />
            <button class="btn ghost sm" id="add-timeline">Add</button>
          </div>
        </div>

        <div class="wire-section">
          <div class="wire-title">Activity Log</div>
          <div class="wire-list" id="activity-list"></div>
          <div class="inline-form">
            <input id="activity_person" placeholder="Person" />
            <input id="activity_dt" type="datetime-local" />
            <input id="activity_text" placeholder="Activity detail" />
            <button class="btn ghost sm" id="add-activity">Add</button>
          </div>
        </div>

        <div class="actions">
          <button class="btn ghost" id="cancel-new">Cancel</button>
          <button class="btn ghost" id="save-draft">Save as Draft</button>
          <button class="btn primary" id="submit-incident">Submit Incident</button>
        </div>
      </div>
    `;

    const applySeverity = (sev) => {
      const badge = document.getElementById('severity-badge');
      if (badge) {
        badge.textContent = sev;
        badge.className = `severity-box severity-${sev.toLowerCase()}`;
      }
      const summary = document.getElementById('severity-summary');
      if (summary) {
        const records = Number(document.getElementById('affected_records').value) || 0;
        const dataTypes = Array.from(document.querySelectorAll('input[name="data_type"]:checked')).map((c) => c.value);
        const highlight = dataTypes.filter((d) => d.includes('Financial') || d.includes('Health') || d.includes('Authentication'));
        const details = [`${records.toLocaleString()} records`];
        if (highlight.length) details.push(`+ ${highlight.join(', ')}`);
        summary.textContent = `${sev} — ${details.join(' ')}`;
      }
    };
    const updateSeverity = () => {
      const records = Number(document.getElementById('affected_records').value) || 0;
      const dataTypes = Array.from(document.querySelectorAll('input[name="data_type"]:checked')).map((c) => c.value);
      const sev = severityFromInputs(records, dataTypes);
      applySeverity(sev);
      return sev;
    };

    document.querySelectorAll('input[name="data_type"]').forEach((cb) => cb.onchange = updateSeverity);
    document.getElementById('affected_records').oninput = updateSeverity;
    applySeverity(updateSeverity());

    document.getElementById('save-draft').onclick = () => handleIncidentSubmit(true, updateSeverity());
    document.getElementById('submit-incident').onclick = () => handleIncidentSubmit(false, updateSeverity());
    const cancelBtn = document.getElementById('cancel-new');
    if (cancelBtn) cancelBtn.onclick = () => { setActiveView('registry-view'); renderRegistry(); };

    const attList = document.getElementById('attachments-list');
    const tlList = document.getElementById('timeline-list');
    const actList = document.getElementById('activity-list');
    const renderExtras = () => {
      attList.innerHTML = extras.attachments.length ? extras.attachments.map((aRaw, idx) => {
        const a = normalizeAttachment(aRaw);
        return `<div class="wire-item">${a.name} ${a.url ? '(click to open after submit)' : ''}</div>`;
      }).join('') : '<div class="detail-subtle">No attachments.</div>';
      tlList.innerHTML = extras.timeline.length ? extras.timeline.map((t) => `<div class="wire-item">${t.date} - ${t.text}</div>`).join('') : '<div class="detail-subtle">No entries.</div>';
      actList.innerHTML = extras.activities.length ? extras.activities.map((a) => `<div class="wire-item">${a.person ? `[${a.person}] ` : ''}${a.date} - ${a.text}</div>`).join('') : '<div class="detail-subtle">No entries.</div>';
    };
    renderExtras();

    const attachInput = document.getElementById('attachment_input');
    const attachFile = document.getElementById('attachment_file');
    document.getElementById('add-attachment').onclick = () => {
      if (attachInput.value.trim()) {
        extras.attachments.push(normalizeAttachment(attachInput.value.trim()));
        attachInput.value = '';
        renderExtras();
      } else {
        attachFile.click();
      }
    };
    attachFile.onchange = (e) => {
      const file = e.target.files?.[0];
      if (file) {
        const url = URL.createObjectURL(file);
        extras.attachments.push({ name: file.name, url });
        renderExtras();
      }
      attachFile.value = '';
    };

    const tlDt = document.getElementById('timeline_dt');
    const tlText = document.getElementById('timeline_text');
    document.getElementById('add-timeline').onclick = () => {
      if (tlDt.value && tlText.value.trim()) {
        const date = tlDt.value.slice(0, 10);
        const time = formatTime(tlDt.value);
        extras.timeline.push({ date, text: `${time} - ${tlText.value.trim()}` });
        tlDt.value = '';
        tlText.value = '';
        renderExtras();
      }
    };

    const actPerson = document.getElementById('activity_person');
    const actDt = document.getElementById('activity_dt');
    const actText = document.getElementById('activity_text');
    document.getElementById('add-activity').onclick = () => {
      if (actDt.value && actText.value.trim()) {
        const date = actDt.value.slice(0, 10);
        const time = formatTime(actDt.value);
        extras.activities.push({ date, text: `${time} - ${actText.value.trim()}`, person: actPerson.value.trim() });
        actPerson.value = '';
        actDt.value = '';
        actText.value = '';
        renderExtras();
      }
    };

    const pdpcRadios = document.querySelectorAll('input[name="pdpc_required"]');
    const pdpcReviewPerson = document.getElementById('pdpc_review_person');
    pdpcRadios.forEach((r) => r.onchange = () => {
      const val = r.value;
      const requiredSelected = r.checked && val !== 'no';
      pdpcReviewPerson.style.display = val === 'review' && r.checked ? 'block' : 'none';
      pdpcNotifiedChk.disabled = !requiredSelected;
      pdpcNotifiedPerson.style.display = requiredSelected && pdpcNotifiedChk.checked ? 'block' : 'none';
      if (!requiredSelected) {
        pdpcNotifiedChk.checked = false;
        pdpcNotifiedPerson.value = '';
      }
    });
    const pdpcNotifiedChk = document.getElementById('pdpc_notified');
    const pdpcNotifiedPerson = document.getElementById('pdpc_notified_person');
    pdpcNotifiedChk.onchange = () => {
      pdpcNotifiedPerson.style.display = pdpcNotifiedChk.checked ? 'block' : 'none';
    };
    const dpoNotifiedChk = document.getElementById('dpo_notified');
    const dpoNotifiedPerson = document.getElementById('dpo_notified_person');
    dpoNotifiedChk.onchange = () => {
      dpoNotifiedPerson.style.display = dpoNotifiedChk.checked ? 'block' : 'none';
    };

    const addUnitBtn = document.getElementById('add-business-unit');
    const newUnitInput = document.getElementById('new_business_unit');
    if (addUnitBtn && newUnitInput) {
      addUnitBtn.onclick = () => {
        const val = newUnitInput.value.trim();
        if (!val) return;
        store.addBusinessUnit(val);
        renderNewIncidentForm();
        document.getElementById('business_unit').value = val;
      };
    }
    const manageBtn = document.getElementById('manage-business-unit');
    if (manageBtn) {
      manageBtn.onclick = () => renderUnitManager();
    }
  }

  function handleIncidentSubmit(draft, forcedSeverity) {
    const dataTypes = Array.from(document.querySelectorAll('input[name="data_type"]:checked')).map((c) => c.value);
    const affected = Number(document.getElementById('affected_records').value) || 0;
    const severity = forcedSeverity || severityFromInputs(affected, dataTypes);
    const pdpcSelection = document.querySelector('input[name="pdpc_required"]:checked')?.value || 'yes';
    const pdpcRequired = pdpcSelection === 'yes';
    const pdpcStatus = pdpcSelection === 'review' ? 'UNDER_REVIEW' : pdpcSelection.toUpperCase();
    const pdpcReviewPerson = document.getElementById('pdpc_review_person')?.value.trim() || '';
    const pdpcNotified = pdpcRequired ? !!document.getElementById('pdpc_notified')?.checked : false;
    const pdpcNotifiedDate = pdpcRequired ? (document.getElementById('pdpc_notified_date')?.value || null) : null;
    const pdpcNotifiedPerson = pdpcRequired ? (document.getElementById('pdpc_notified_person')?.value.trim() || '') : '';
    const dpoNotified = !!document.getElementById('dpo_notified')?.checked;
    const dpoNotifiedDate = document.getElementById('dpo_notified_date')?.value || null;
    const dpoNotifiedPerson = document.getElementById('dpo_notified_person')?.value.trim() || '';
    // validation for required names
    if (pdpcStatus === 'UNDER_REVIEW' && !pdpcReviewPerson) {
      alert('Please provide the review person for PDPC status under review.');
      return;
    }
    if (pdpcRequired && pdpcNotified && !pdpcNotifiedPerson) {
      alert('Please provide the person-in-charge for PDPC notified.');
      return;
    }
    if (dpoNotified && !dpoNotifiedPerson) {
      alert('Please provide the person-in-charge for DPO notified.');
      return;
    }
    const payload = {
      incident_date: document.getElementById('incident_date').value,
      discovered_date: document.getElementById('discovered_date').value,
      breach_type: document.getElementById('breach_type').value,
      business_unit: document.getElementById('business_unit').value,
      affected_records: affected,
      data_types: dataTypes.length ? dataTypes : ['Other Sensitive Data'],
      severity,
      root_cause: document.getElementById('root_cause').value,
      description: document.getElementById('description').value || 'No description provided.',
      lessons_learned: document.getElementById('discovered_how').value || '',
      remediation_actions: document.getElementById('immediate_actions').value || '',
      detection_method: document.getElementById('discovered_how').value || '',
      immediate_actions: document.getElementById('immediate_actions').value || '',
      pdpc_notification_required: pdpcRequired,
      pdpc_status: pdpcStatus,
      pdpc_review_person: pdpcReviewPerson,
      pdpc_notified: pdpcNotified,
      pdpc_notified_date: pdpcNotifiedDate,
      pdpc_notified_person: pdpcNotifiedPerson,
      dpo_guidance_issued: dpoNotified,
      dpo_notified_date: dpoNotifiedDate,
      dpo_notified_person: dpoNotifiedPerson,
      attachments: [...newIncidentExtras.attachments],
      timeline: [...newIncidentExtras.timeline],
      activities: [...newIncidentExtras.activities],
      follow_up_actions: [],
      preventive_measures: '',
      improvements: ''
    };
    if (currentEditIncidentId && !draft) {
      const editId = currentEditIncidentId;
      store.updateIncident(editId, payload);
      currentEditIncidentId = null;
      newIncidentExtras = { attachments: [], timeline: [], activities: [] };
      setActiveView('detail-view');
      renderIncidentDetail(editId);
      renderDashboard();
      renderRegistry();
    } else if (draft) {
      const savedDraft = store.addIncident(payload, true);
      newIncidentExtras = { attachments: [], timeline: [], activities: [] };
      renderDraftOverlay(savedDraft);
    } else {
      const incident = store.addIncident(payload, false);
      newIncidentExtras = { attachments: [], timeline: [], activities: [] };
      setActiveView('detail-view');
      renderIncidentDetail(incident.id);
      renderDashboard();
      renderRegistry();
    }
  }
function renderCompliance() {
    const container = document.getElementById('compliance-view');
    const incidents = store.listIncidents();
    const sqlDataset = buildSqlDataset(incidents);
    const units = store.listUnits().map((u) => {
      const unitIncidents = incidents.filter((i) => i.business_unit === u);
      const score = complianceScore(unitIncidents);
      const avgResponse = averageResponse(unitIncidents);
      const trend = trendValue(unitIncidents);
      const critical = unitIncidents.filter((i) => i.severity === 'CRITICAL').length;
      return { unit: u, score, incidents: unitIncidents.length, avgResponse, trend, critical };
    }).sort((a, b) => b.score - a.score);
    const vulnSummary = summarizeVulnerabilities(incidents);
    const vulnTopFive = vulnSummary.items.slice(0, 5);
    const sampleButtons = SQL_SAMPLE_QUERIES.map((q) => `<button class="btn ghost sm" data-sql-sample="${q.id}">${q.label}</button>`).join('');
    const analyticsSnapshot = buildAnalyticsSnapshot(incidents);

    container.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">Compliance Monitoring Dashboard</div>
          <div class="legend">
            <span class="badge-inline"><span class="indicator ok"></span> Excellent (90-100)</span>
            <span class="badge-inline"><span class="indicator medium"></span> Good (78-89)</span>
            <span class="badge-inline"><span class="indicator warn"></span> Needs Improvement (58-77)</span>
            <span class="badge-inline"><span class="indicator critical"></span> Critical (&lt; 58)</span>
          </div>
        </div>

        <div class="panel">
          <div class="panel-title">Business Unit Compliance Scores</div>
          <table class="table">
            <thead>
              <tr><th>Business Unit</th><th>Score</th><th>Incidents</th><th>Avg Resp</th><th>Trend</th></tr>
            </thead>
            <tbody>
              ${units.map((u) => `
                <tr>
                  <td>${u.unit}</td>
                  <td><span class="badge">${u.score}</span></td>
                  <td>${u.incidents} (${u.critical} crit)</td>
                  <td>${u.avgResponse || '-'}</td>
                  <td>${trendBadge(u.trend)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div class="panel">
          <div class="panel-title">Data Protection Maturity</div>
          <div class="list">
            ${units.map((u) => `
              <div>
                <div class="muted">${u.unit}</div>
                ${stackedBar(u.score)}
              </div>
            `).join('')}
          </div>
        </div>

        <div class="panel">
          <div class="panel-title">Recommended Actions</div>
          <div class="list">
            ${recommendations(units)}
          </div>
          <div class="actions" style="margin-top:10px;">
            <button class="btn primary" id="export-compliance">Export Data (Audit Trail)</button>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">Recurring Vulnerability Classes</div>
            <div class="muted small">Pattern detection surfaces five recurring classes and their loss frequency share to support reporting and target training initiatives.</div>
          </div>
        </div>
        <div class="table-wrap">
          <table class="table compact">
            <thead>
              <tr><th>Class</th><th>Incidents</th><th>Open</th><th>Loss Frequency</th><th>Typical Severity</th><th>Example</th></tr>
            </thead>
            <tbody>
              ${vulnTopFive.map((v) => `
                <tr>
                  <td>${v.label}</td>
                  <td>${v.count}</td>
                  <td>${v.open}</td>
                  <td>${v.frequency}%</td>
                  <td><span class="chip status ${v.topSeverity.toLowerCase()}">${v.topSeverity}</span></td>
                  <td>${v.sample || '-'}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div>
            <div class="panel-title">SQL Analytics Fast Lane</div>
            <div class="muted small">Prebuilt SQL cuts compliance reporting from ~8 hours to a quick 15-minute in-browser run. Edit and run ad-hoc queries without any backend.</div>
          </div>
          <div class="actions">
            ${sampleButtons}
            <button class="btn primary sm" id="sql-run">Run SQL</button>
          </div>
        </div>
        <div class="form-group">
          <label for="sql-query">SQL Query</label>
          <textarea id="sql-query" class="sql-area" spellcheck="false"></textarea>
        </div>
        <div class="sql-meta" id="sql-status"></div>
        <div id="sql-results"></div>
      </div>
    `;

    const runButton = document.getElementById('sql-run');
    const sqlArea = document.getElementById('sql-query');
    const sqlStatus = document.getElementById('sql-status');
    const sqlResults = document.getElementById('sql-results');
    let currentSample = SQL_SAMPLE_QUERIES[0];
    if (sqlArea && currentSample) {
      sqlArea.value = currentSample.sql;
    }
    const runSqlPanel = (query, sampleId = currentSample?.id) => {
      if (!sqlStatus || !sqlResults) return;
      const result = runSqlQuery(query, sqlDataset, sampleId);
      sqlStatus.textContent = result.usedFallback
        ? 'SQL engine not available; showing built-in analytics fallback.'
        : 'SQL executed locally via AlaSQL (no backend calls).';
      if (result.error) {
        sqlStatus.textContent += ` ${result.error}`;
      }
      sqlResults.innerHTML = tableHtml(result.rows);
    };
    if (runButton && sqlArea) {
      runButton.onclick = () => runSqlPanel(sqlArea.value, currentSample?.id);
    }
    document.querySelectorAll('[data-sql-sample]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const sample = SQL_SAMPLE_QUERIES.find((s) => s.id === btn.dataset.sqlSample);
        if (sample && sqlArea) {
          currentSample = sample;
          sqlArea.value = sample.sql;
          runSqlPanel(sample.sql, sample.id);
        }
      });
    });
    if (sqlArea && currentSample) {
      runSqlPanel(currentSample.sql, currentSample.id);
    }

    document.getElementById('export-compliance').onclick = () => exportIncident(incidents, 'compliance-summary', { analytics: analyticsSnapshot });
  };

  const stackedBar = (score) => {
    const clamp = Math.max(0, Math.min(100, score));
    const colors = [
      { color: '#f87171', size: clamp >= 0 ? Math.min(clamp, 30) : 0 },
      { color: '#facc15', size: clamp > 30 ? Math.min(clamp - 30, 20) : 0 },
      { color: '#60a5fa', size: clamp > 50 ? Math.min(clamp - 50, 20) : 0 },
      { color: '#86efac', size: clamp > 70 ? Math.min(clamp - 70, 30) : 0 }
    ];
    const total = colors.reduce((a, c) => a + c.size, 0) || 1;
    return `
      <div class="stacked-bar">
        ${colors.map((c) => `<div class="stacked-seg" style="width:${(c.size / total) * 100}%;background:${c.color}"></div>`).join('')}
      </div>
      <div class="muted">Score ${score}</div>
    `;
  };

  const trendBadge = (value) => {
    const sign = value > 0 ? '+' : '';
    const tone = value > 0 ? 'success' : value === 0 ? 'muted' : 'danger';
    const color = tone === 'success' ? 'var(--success)' : tone === 'danger' ? 'var(--danger)' : 'var(--muted)';
    return `<span style="color:${color};font-weight:700;">${sign}${value}</span>`;
  };

  const recommendations = (units) => {
    const urgent = units.filter((u) => u.score < 60);
    const improve = units.filter((u) => u.score >= 60 && u.score < 75);
    const stable = units.filter((u) => u.score >= 90);
    const buildList = (title, items, tone) => {
      if (!items.length) return '';
      const color = tone === 'danger' ? 'var(--danger)' : tone === 'warn' ? 'var(--warn)' : 'var(--success)';
      return `
        <div class="callout" style="border-color:${color};">
          <div class="panel-title" style="color:${color};">${title}</div>
          <ul>
            ${items.map((u) => `<li>${u.unit}: ${u.critical} critical, ${u.incidents} incidents - avg resp ${u.avgResponse || '-'}</li>`).join('')}
          </ul>
        </div>
      `;
    };
    return `${buildList('Urgent', urgent, 'danger')}${buildList('Needs Improvement', improve, 'warn')}${buildList('On Track', stable, 'success')}`;
  };

  const complianceScore = (incidents) => {
    if (!incidents.length) return 100;
    let score = 100;
    incidents.forEach((i) => {
      if (i.severity === 'CRITICAL') score -= 18;
      else if (i.severity === 'HIGH') score -= 12;
      else if (i.severity === 'MEDIUM') score -= 7;
      else score -= 4;

      if (i.response_time_hours && i.response_time_hours <= 24) score += 3;
      if (i.status === 'RESOLVED') score += 2;
      if (i.pdpc_notification_required && !i.pdpc_notified) score -= 4;
    });
    return Math.max(0, Math.min(100, Math.round(score)));
  };

  const averageResponse = (incidents) => {
    const withTime = incidents.filter((i) => i.response_time_hours);
    if (!withTime.length) return null;
    const avg = withTime.reduce((acc, i) => acc + i.response_time_hours, 0) / withTime.length;
    return `${avg.toFixed(1)}h`;
  };

  const trendValue = (incidents) => {
    const recent = incidents.filter((i) => daysBetween(i.discovered_date, new Date().toISOString().slice(0, 10)) <= 30).length;
    const previous = incidents.filter((i) => {
      const days = daysBetween(i.discovered_date, new Date().toISOString().slice(0, 10));
      return days > 30 && days <= 60;
    }).length;
    return recent - previous;
  };

  const exportIncident = (incidents, filename, options = {}) => {
    const style = `
      <style>
        body { font-family: Arial, sans-serif; color: #0f172a; margin: 20px; }
        h2 { margin-bottom: 4px; }
        h3 { margin: 12px 0 6px; }
        .card { border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; margin-bottom: 14px; }
        .muted { color: #475569; font-size: 13px; }
        .section { margin: 10px 0; }
        .title { text-transform: uppercase; letter-spacing: 0.04em; font-size: 12px; color: #475569; margin-bottom: 6px; font-weight: 700; }
        ul { margin: 6px 0 0 18px; }
        li { margin: 2px 0; }
        .tag { display: inline-block; padding: 4px 8px; border: 1px solid #cbd5e1; border-radius: 6px; margin-right: 6px; font-size: 12px; color: #0f172a; }
        .mono { font-family: "Courier New", monospace; }
        table { width: 100%; border-collapse: collapse; margin: 8px 0; }
        th, td { border: 1px solid #e5e7eb; padding: 6px 8px; text-align: left; font-size: 13px; }
        th { background: #f8fafc; }
        h4 { margin: 6px 0 4px; }
      </style>
    `;
    const renderList = (items, empty) => (items && items.length ? `<ul>${items.map((t) => `<li>${t}</li>`).join('')}</ul>` : `<div class="muted">${empty}</div>`);
    const renderTableInline = (rows) => {
      if (!rows || !rows.length) return '<div class="muted">No rows returned.</div>';
      const headers = Object.keys(rows[0]);
      const fmt = (val) => {
        if (typeof val === 'boolean') return val ? 'Yes' : 'No';
        return val ?? '';
      };
      return `
        <table>
          <thead><tr>${headers.map((h) => `<th>${h}</th>`).join('')}</tr></thead>
          <tbody>
            ${rows.map((r) => `<tr>${headers.map((h) => `<td>${fmt(r[h])}</td>`).join('')}</tr>`).join('')}
          </tbody>
        </table>
      `;
    };
    const analytics = options.analytics || buildAnalyticsSnapshot(incidents);
    const analyticsBlock = analytics ? `
      <div class="card">
        <div class="title">SQL Analytics Snapshot</div>
        <div class="muted">Generated in-browser; prebuilt SQL queries compress compliance reporting from hours to minutes.</div>
        <h4>Coverage by Business Unit</h4>
        ${renderTableInline(analytics.coverage)}
        <h4>Throughput by Severity</h4>
        ${renderTableInline(analytics.throughput)}
        <h4>Audit Trail Snapshot</h4>
        ${renderTableInline((analytics.auditTrail || []).slice(0, 50))}
      </div>
    ` : '';
    const html = `
      <html><head>${style}</head><body>
        <h2>PDPC / Audit Incident Report</h2>
        ${analyticsBlock}
        ${incidents.map((i) => `
          <div class="card">
            <div class="section">
              <span class="tag">${i.incident_id}</span>
              <span class="tag">${i.severity}</span>
              <span class="tag">${i.status}</span>
              <span class="tag">${i.business_unit}</span>
            </div>
            <div class="section">
              <div class="title">Incident Summary</div>
              <div><strong>Type:</strong> ${i.breach_type}</div>
              <div><strong>Root Cause:</strong> ${i.root_cause}</div>
              <div><strong>Dates:</strong> Incident ${i.incident_date} | Discovered ${i.discovered_date} | Reported ${i.reported_date || '-'} | Resolved ${i.resolved_date || '-'}</div>
              <div><strong>Impact:</strong> ${i.affected_records} records</div>
              <div><strong>Data Types:</strong> ${i.data_types.join(', ')}</div>
              <div><strong>Response Time:</strong> ${i.response_time_hours ? `${i.response_time_hours} hours` : 'n/a'}</div>
              <div><strong>Detection Method:</strong> ${i.detection_method || '-'}</div>
            </div>
            <div class="section">
              <div class="title">Description</div>
              <div>${i.description || 'No description provided.'}</div>
            </div>
            <div class="section">
              <div class="title">Remediation Actions</div>
              <div>${i.remediation_actions || 'No remediation captured.'}</div>
            </div>
            <div class="section">
              <div class="title">Follow-up Actions</div>
              ${renderList(i.follow_up_actions, 'No follow-up actions.')}
            </div>
            <div class="section">
              <div class="title">Immediate Actions</div>
              <div>${i.immediate_actions || 'Not documented.'}</div>
            </div>
            <div class="section">
              <div class="title">Compliance</div>
              <div>PDPC Notification: ${i.pdpc_notification_required ? 'Required' : 'Not Required'}</div>
              <div>PDPC Status: ${i.pdpc_status || (i.pdpc_notification_required ? 'YES' : 'NO')} ${i.pdpc_review_person ? `(${i.pdpc_review_person})` : ''}</div>
              <div>PDPC Notified: ${i.pdpc_notified ? 'Yes' : 'No'} ${i.pdpc_notified_date ? `(${i.pdpc_notified_date})` : ''} ${i.pdpc_notified_person ? ` - ${i.pdpc_notified_person}` : ''}</div>
              <div>DPO Guidance Issued: ${i.dpo_guidance_issued ? 'Yes' : 'No'} ${i.dpo_notified_date ? `(${i.dpo_notified_date})` : ''} ${i.dpo_notified_person ? ` - ${i.dpo_notified_person}` : ''}</div>
              <div>Guidance: ${i.lessons_learned || 'Not documented.'}</div>
              <div>Preventive Measures: ${i.preventive_measures || 'Not documented.'}</div>
              <div>Improvements: ${i.improvements || 'Not documented.'}</div>
            </div>
            <div class="section">
              <div class="title">Audit Trail</div>
              <div><strong>Compliance Updates</strong></div>
              ${renderList((i.compliance_history || []).map((h) => `${h.date || ''}: ${h.text}`), 'No compliance changes recorded.')}
              <div><strong>Change History</strong></div>
              ${renderList((i.history || []).map((h) => `${h.date ? h.date.slice(0, 10) : ''} ${h.text}`), 'No field-level edits recorded.')}
            </div>
            <div class="section">
              <div class="title">Attachments (${(i.attachments || []).length})</div>
              ${renderList((i.attachments || []).map((a) => {
                const att = normalizeAttachment(a);
                return att.url ? `<a href="${att.url}" target="_blank">${att.name}</a>` : att.name;
              }), 'No attachments.')}
            </div>
            <div class="section">
              <div class="title">Timeline</div>
              ${renderList((i.timeline || []).map((t) => `${t.date} - ${t.text}`), 'No entries.')}
            </div>
            <div class="section">
              <div class="title">Activity Log</div>
              ${renderList((i.activities || []).map((a) => `${a.person ? `[${a.person}] ` : ''}${a.date} - ${a.text}`), 'No entries.')}
            </div>
            <div class="section">
              <div class="title">Notes</div>
              ${renderList((i.notes || []).map((n) => `${n.date}: ${n.text}`), 'No notes.')}
            </div>
          </div>
        `).join('')}
      </body></html>
    `;
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportReport = () => {
    const incidents = store.listIncidents();
    exportIncident(incidents, 'pdpc-report', { analytics: buildAnalyticsSnapshot(incidents) });
  };

  const hookGlobalEvents = () => {
    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        setActiveView(btn.dataset.view);
        if (btn.dataset.view === 'dashboard-view') renderDashboard();
        if (btn.dataset.view === 'registry-view') renderRegistry();
        if (btn.dataset.view === 'new-incident-view') renderNewIncidentForm();
        if (btn.dataset.view === 'compliance-view') renderCompliance();
        if (btn.dataset.view === 'detail-view') {
          if (currentDetailId) {
            renderIncidentDetail(currentDetailId);
          } else {
            renderDetailPlaceholder();
          }
        }
      });
    });

    document.getElementById('export-report').onclick = exportReport;
    document.getElementById('log-incident-shortcut').onclick = () => {
      setActiveView('new-incident-view');
      renderNewIncidentForm();
    };
    const resetBtn = document.getElementById('reset-data');
    if (resetBtn) {
      resetBtn.onclick = () => {
        store.reset();
        newIncidentExtras = { attachments: [], timeline: [], activities: [] };
        renderDashboard();
        renderRegistry();
        renderNewIncidentForm();
        renderCompliance();
        renderDetailPlaceholder();
        setActiveView('dashboard-view');
      };
    }

    document.body.addEventListener('click', (e) => {
      const viewId = e.target.dataset.viewId;
      const noteId = e.target.dataset.noteId;
      const resolveId = e.target.dataset.resolveId;
      const followId = e.target.dataset.followupId;

      if (viewId) {
        setActiveView('detail-view');
        renderIncidentDetail(viewId);
      }
      if (noteId) {
        const text = prompt('Add note');
        if (text) {
          store.addNote(noteId, text);
          renderRegistry();
          if (currentDetailId === noteId) renderIncidentDetail(noteId);
        }
      }
      if (followId) {
        const text = prompt('Add follow-up action');
        if (text) {
          const target = store.getIncident ? store.getIncident(followId) : null;
          const actions = target?.follow_up_actions || [];
          store.updateIncident(followId, { follow_up_actions: [...actions, text] });
          renderRegistry();
          if (currentDetailId === followId) renderIncidentDetail(followId);
        }
      }
      if (resolveId) {
        const lesson = prompt('Lessons learned (required):');
        if (!lesson) return;
        const preventive = prompt('Preventive measures (required):');
        if (!preventive) return;
        const improvements = prompt('General improvements (required):');
        if (!improvements) return;
        store.updateIncident(resolveId, {
          status: 'RESOLVED',
          resolved_date: new Date().toISOString().slice(0, 10),
          lessons_learned: lesson,
          preventive_measures: preventive,
          improvements
        });
        renderRegistry();
        renderDashboard();
        if (currentDetailId === resolveId) renderIncidentDetail(resolveId);
      }
    });
  };

  // Safe runner to surface errors
  const safeRender = (fn, label) => {
    try { fn(); } catch (err) {
      console.error(label + ' failed', err);
      const pre = document.createElement('pre');
      pre.style.padding = '12px';
      pre.style.background = '#330';
      pre.style.color = '#fdd';
      pre.textContent = `${label} failed: ${err.message}
${err.stack || ''}`;
      document.body.prepend(pre);
    }
  };

  // Initial render
  hookGlobalEvents();
  safeRender(renderDashboard, 'renderDashboard');
  safeRender(renderRegistry, 'renderRegistry');
  safeRender(renderNewIncidentForm, 'renderNewIncidentForm');
  safeRender(renderCompliance, 'renderCompliance');
  safeRender(renderDetailPlaceholder, 'renderDetailPlaceholder');
})();
