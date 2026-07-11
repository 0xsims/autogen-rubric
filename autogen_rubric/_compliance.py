# ── Rubric Compliance Fields ──────────────────────────────────────────────
# Auto-populated and customer-supplied compliance fields.
# All optional — backward compatible with existing integrations.

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import hashlib, json

RUBRIC_EVENT_TYPES = [
    'inference.decision','inference.recommendation','inference.classification',
    'inference.generation','inference.screening','inference.scoring',
    'human.review','human.override','human.approval','human.rejection','human.escalation',
    'model.deployment','model.version-change','model.retirement',
    'model.training-complete','model.validation-complete','model.calibration',
    'data.dataset-registered','data.dataset-version','data.quality-check','data.drift-detected',
    'risk.assessment','risk.mitigation-applied','risk.threshold-breach','risk.bias-detected',
    'incident.detected','incident.reported','incident.mitigated','incident.resolved','incident.false-positive',
    'performance.benchmark','performance.drift-detected','performance.audit','performance.monitoring',
    'compliance.conformity-assessed','compliance.declaration-signed',
    'compliance.standards-applied','compliance.registration','compliance.post-market-review',
]

OUTCOME_TYPES = [
    'approved','rejected','referred','deferred','escalated',
    'flagged','generated','classified','scored','no-action',
]

RISK_LEVELS = ['minimal','low','medium','high','critical']
MODEL_TIERS = ['tier-1','tier-2','tier-3']
VALIDATION_STATUSES = [
    'in-development','pending-validation','validated',
    'conditionally-approved','approved','under-review','suspended','retired',
]
INCIDENT_SEVERITIES = ['minor','moderate','serious','critical']


@dataclass
class ComplianceFields:
    """
    Layer 2 compliance envelope fields.
    All optional — add progressively as compliance requirements grow.
    """
    # Group A — Event classification
    rubric_event_type: Optional[str] = None       # MOST IMPORTANT — classifies the event
    system_id: Optional[str] = None               # Stable system identifier
    system_version: Optional[str] = None          # Semantic version of deployed system

    # Group B — Model identity
    model_version: Optional[str] = None           # Underlying model version
    model_hash: Optional[str] = None              # SHA256 of model weights/card
    upstream_model_id: Optional[str] = None       # Third-party model called (TPRM)

    # Group C — Decision quality
    outcome: Optional[str] = None                 # Structured decision outcome
    confidence: Optional[float] = None            # 0.0-1.0 confidence score
    latency_ms: Optional[int] = None              # Auto-populated if not provided
    input_hash: Optional[str] = None              # SHA256 of input (privacy-safe)
    output_hash: Optional[str] = None             # SHA256 of output

    # Group D — Temporal context (Art. 12(3)(a) — mandated for Annex III)
    session_started_at: Optional[str] = None      # ISO8601 — auto-populated
    session_ended_at: Optional[str] = None        # ISO8601 — auto-populated

    workflow_step: Optional[str] = None           # Step in multi-agent pipeline

    # Group E — Human oversight (Art. 14, Art. 12(3)(d))
    reviewer_id: Optional[str] = None             # SHA256 of reviewer identity
    review_decision: Optional[str] = None         # confirmed/overridden/escalated
    oversight_mechanism: Optional[str] = None     # 4-eyes-principle, etc.
    human_override_reason: Optional[str] = None   # Reason for override (max 500 chars)

    # Group F — Risk and population
    risk_level: Optional[str] = None              # minimal/low/medium/high/critical
    risk_factors: Optional[List[str]] = None      # Risk factors list (max 10)
    population_group: Optional[str] = None        # Affected population (bias monitoring)
    affected_person_count: Optional[int] = None   # Number of people affected

    # Group G — Regulatory context
    jurisdiction: Optional[List[str]] = None      # ['EU','DE','US','TX']
    regulatory_context: Optional[List[str]] = None # ['EU-AI-ACT','SR-11-7']
    standards_applied: Optional[List[str]] = None # ['NIST-AI-RMF-1.0','ISO-42001-2023']

    # Group H — Incident
    incident_id: Optional[str] = None             # Groups incident attestations
    incident_severity: Optional[str] = None       # minor/moderate/serious/critical

    # Group I — SR 11-7 (Financial services)
    model_tier: Optional[str] = None              # tier-1/tier-2/tier-3
    validation_status: Optional[str] = None       # approved/pending-validation/etc.
    validation_id: Optional[str] = None           # References validation attestation
    exception_flag: Optional[bool] = None         # True if decision is an exception

    # Group J — Data governance (Art. 12(3)(b))
    dataset_id: Optional[str] = None              # Reference dataset identifier
    dataset_version: Optional[str] = None         # Dataset version

    # Customer tags (Layer 5)
    tags: Optional[Dict[str, str]] = None         # Max 20 key-value pairs

    def to_dict(self) -> Dict[str, Any]:
        """Convert to camelCase dict for API payload."""
        mapping = {
            'rubric_event_type': 'rubricEventType',
            'system_id': 'systemId',
            'system_version': 'systemVersion',
            'model_version': 'modelVersion',
            'model_hash': 'modelHash',
            'upstream_model_id': 'upstreamModelId',
            'outcome': 'outcome',
            'confidence': 'confidence',
            'latency_ms': 'latencyMs',
            'input_hash': 'inputHash',
            'output_hash': 'outputHash',
            'session_started_at': 'sessionStartedAt',
            'session_ended_at': 'sessionEndedAt',
            'workflow_step': 'workflowStep',
            'reviewer_id': 'reviewerId',
            'review_decision': 'reviewDecision',
            'oversight_mechanism': 'oversightMechanism',
            'human_override_reason': 'humanOverrideReason',
            'risk_level': 'riskLevel',
            'risk_factors': 'riskFactors',
            'population_group': 'populationGroup',
            'affected_person_count': 'affectedPersonCount',
            'jurisdiction': 'jurisdiction',
            'regulatory_context': 'regulatoryContext',
            'standards_applied': 'standardsApplied',
            'incident_id': 'incidentId',
            'incident_severity': 'incidentSeverity',
            'model_tier': 'modelTier',
            'validation_status': 'validationStatus',
            'validation_id': 'validationId',
            'exception_flag': 'exceptionFlag',
            'dataset_id': 'datasetId',
            'dataset_version': 'datasetVersion',
            'tags': 'tags',
        }
        result = {}
        for snake, camel in mapping.items():
            val = getattr(self, snake)
            if val is not None:
                result[camel] = val
        return result

    @staticmethod
    def hash_input(data: Any, max_bytes: int = 4096) -> str:
        """SHA256 of input data — for inputHash/outputHash fields."""
        try:
            serialized = json.dumps(data, sort_keys=True, default=str).encode()[:max_bytes]
        except Exception:
            serialized = str(data).encode()[:max_bytes]
        return hashlib.sha256(serialized).hexdigest()

    @staticmethod
    def hash_reviewer(reviewer_id: str) -> str:
        """SHA256 of reviewer identity — never store raw IDs."""
        return hashlib.sha256(reviewer_id.encode()).hexdigest()
