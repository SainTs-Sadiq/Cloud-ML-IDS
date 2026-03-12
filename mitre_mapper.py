"""
mitre_mapper.py
---------------
Maps AWS CloudTrail events to MITRE ATT&CK for Cloud (IaaS) techniques.
Covers all major tactic categories with confidence scoring and severity levels.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import re


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    confidence: str          # "High" | "Medium" | "Low"
    severity: int            # 1 (low) – 10 (critical)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "severity": self.severity,
            "description": self.description,
        }


@dataclass
class MappingRule:
    """A single mapping rule: event pattern → MITRE technique."""
    event_pattern: Optional[str]            # substring match on eventName (None = match all)
    error_pattern: Optional[str]            # substring match on errorCode  (None = any/none)
    require_error: bool                     # True = errorCode must be present
    technique: MitreTechnique
    service_filter: Optional[list[str]] = field(default=None)  # restrict to AWS services

    def matches(self, event_name: str, error_code: Optional[str], aws_service: str) -> bool:
        # Service filter
        if self.service_filter and aws_service not in self.service_filter:
            return False

        # Event name match
        if self.event_pattern and self.event_pattern not in event_name:
            return False

        # Error code logic
        if self.require_error and not error_code:
            return False
        if self.error_pattern and (not error_code or self.error_pattern not in str(error_code)):
            return False

        return True


# ---------------------------------------------------------------------------
# Rule Catalogue  (extend freely)
# ---------------------------------------------------------------------------

_RULES: list[MappingRule] = [

    # ── Discovery ─────────────────────────────────────────────────────────
    MappingRule("List", None, False,
        MitreTechnique("T1526", "Cloud Service Discovery", "Discovery", "Medium", 3,
                       "Adversary lists available cloud services/resources to map the environment.")),

    MappingRule("Describe", None, False,
        MitreTechnique("T1580", "Cloud Infrastructure Discovery", "Discovery", "Medium", 3,
                       "Enumeration of cloud infrastructure details (instances, VPCs, etc.).")),

    MappingRule("Get", None, False,
        MitreTechnique("T1613", "Container and Resource Discovery", "Discovery", "Low", 2,
                       "Read/get API calls used to understand resource configuration.")),

    MappingRule("GetCallerIdentity", None, False,
        MitreTechnique("T1033", "System Owner/User Discovery", "Discovery", "Medium", 4,
                       "Adversary checks which IAM identity is being used.")),

    # ── Credential Access ─────────────────────────────────────────────────
    MappingRule("ConsoleLogin", "Failed", True,
        MitreTechnique("T1110.001", "Brute Force: Password Guessing", "Credential Access", "High", 8,
                       "Repeated failed console logins indicate password-guessing activity.")),

    MappingRule("ConsoleLogin", "Failed authentication", True,
        MitreTechnique("T1110.001", "Brute Force: Password Guessing", "Credential Access", "High", 8,
                       "Repeated failed console logins indicate password-guessing activity.")),

    MappingRule("AssumeRole", "AccessDenied", True,
        MitreTechnique("T1110.003", "Brute Force: Password Spraying", "Credential Access", "Medium", 6,
                       "Repeated AccessDenied on AssumeRole suggests credential probing.")),

    MappingRule("GetSessionToken", None, False,
        MitreTechnique("T1550.001", "Use Alternate Authentication Material: STS", "Credential Access", "Medium", 5,
                       "Short-lived STS tokens obtained—may indicate lateral movement prep.")),

    # ── Defense Evasion ───────────────────────────────────────────────────
    MappingRule("StopLogging", None, False,
        MitreTechnique("T1562.008", "Impair Defenses: Disable Cloud Logs", "Defense Evasion", "High", 10,
                       "CloudTrail logging disabled—attacker covering tracks.")),

    MappingRule("DeleteTrail", None, False,
        MitreTechnique("T1562.008", "Impair Defenses: Disable Cloud Logs", "Defense Evasion", "High", 10,
                       "CloudTrail trail deleted—critical log integrity breach.")),

    MappingRule("UpdateTrail", None, False,
        MitreTechnique("T1562.008", "Impair Defenses: Disable Cloud Logs", "Defense Evasion", "Medium", 7,
                       "Trail configuration changed—may redirect or suppress logs.")),

    MappingRule("DeleteFlowLogs", None, False,
        MitreTechnique("T1562.008", "Impair Defenses: Disable Cloud Logs", "Defense Evasion", "High", 9,
                       "VPC Flow Logs deleted—network visibility removed.")),

    MappingRule("DisableKey", None, False,
        MitreTechnique("T1486", "Data Encrypted for Impact", "Impact", "High", 9,
                       "KMS key disabled—may cause data unavailability.")),

    # ── Persistence ───────────────────────────────────────────────────────
    MappingRule("CreateUser", None, False,
        MitreTechnique("T1136.003", "Create Account: Cloud Account", "Persistence", "High", 8,
                       "New IAM user created—may be a backdoor account.")),

    MappingRule("CreateAccessKey", None, False,
        MitreTechnique("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence", "High", 8,
                       "New access key created—potential persistent access mechanism.")),

    MappingRule("AttachUserPolicy", None, False,
        MitreTechnique("T1098.003", "Account Manipulation: Add Office 365 Global Administrator Role", "Persistence", "High", 8,
                       "Policy attached directly to user—privilege escalation attempt.")),

    MappingRule("AttachRolePolicy", None, False,
        MitreTechnique("T1098.003", "Account Manipulation: Additional Roles", "Persistence", "Medium", 6,
                       "Policy attached to role—role permissions expanded.")),

    MappingRule("PutUserPolicy", None, False,
        MitreTechnique("T1098.001", "Account Manipulation: Additional Cloud Credentials", "Persistence", "High", 7,
                       "Inline policy added to user—potential privilege escalation.")),

    # ── Privilege Escalation ──────────────────────────────────────────────
    MappingRule("CreateRole", None, False,
        MitreTechnique("T1078.004", "Valid Accounts: Cloud Accounts", "Privilege Escalation", "Medium", 6,
                       "New IAM role created—check trust relationship and permissions.")),

    MappingRule("PassRole", None, False,
        MitreTechnique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation", "High", 8,
                       "PassRole allows passing elevated permissions to a service.")),

    # ── Exfiltration ──────────────────────────────────────────────────────
    MappingRule("GetObject", None, False,
        MitreTechnique("T1530", "Data from Cloud Storage Object", "Exfiltration", "Medium", 5,
                       "S3 object(s) retrieved—monitor for bulk or sensitive data access."),
        service_filter=["s3"]),

    MappingRule("PutBucketPolicy", None, False,
        MitreTechnique("T1537", "Transfer Data to Cloud Account", "Exfiltration", "High", 8,
                       "S3 bucket policy modified—may expose data to external accounts."),
        service_filter=["s3"]),

    MappingRule("ModifySnapshotAttribute", None, False,
        MitreTechnique("T1537", "Transfer Data to Cloud Account", "Exfiltration", "High", 9,
                       "EBS snapshot shared externally—data exfiltration via snapshot.")),

    # ── Lateral Movement ─────────────────────────────────────────────────
    MappingRule("AssumeRole", None, False,
        MitreTechnique("T1550.001", "Use Alternate Authentication Material", "Lateral Movement", "Medium", 5,
                       "Role assumed—track cross-account or unexpected role assumptions.")),

    # ── Impact ────────────────────────────────────────────────────────────
    MappingRule("DeleteBucket", None, False,
        MitreTechnique("T1485", "Data Destruction", "Impact", "High", 9,
                       "S3 bucket deleted—potentially destructive action.")),

    MappingRule("TerminateInstances", None, False,
        MitreTechnique("T1529", "System Shutdown/Reboot", "Impact", "High", 8,
                       "EC2 instances terminated—service disruption possible.")),

    MappingRule("DeleteDBInstance", None, False,
        MitreTechnique("T1485", "Data Destruction", "Impact", "High", 10,
                       "RDS instance deletion—critical data loss risk.")),

    # ── Initial Access ────────────────────────────────────────────────────
    MappingRule("ConsoleLogin", None, False,
        MitreTechnique("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access", "Low", 2,
                       "Successful console login—baseline for detecting anomalous sessions.")),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def map_to_mitre(
    event_name: str,
    error_code: Optional[str],
    aws_service: str,
) -> list[dict]:
    """
    Map a CloudTrail event to zero or more MITRE ATT&CK techniques.

    Args:
        event_name:  CloudTrail ``eventName`` field.
        error_code:  CloudTrail ``errorCode`` field (None if no error).
        aws_service: Short service name extracted from ``eventSource``
                     (e.g. ``"s3"``, ``"iam"``).

    Returns:
        Deduplicated list of technique dicts sorted by descending severity.
    """
    event_name = str(event_name or "")
    error_code = str(error_code) if error_code and str(error_code) not in ("None", "") else None
    aws_service = str(aws_service or "").lower()

    seen: set[str] = set()
    results: list[MitreTechnique] = []

    for rule in _RULES:
        if rule.matches(event_name, error_code, aws_service):
            key = rule.technique.technique_id
            if key not in seen:
                seen.add(key)
                results.append(rule.technique)

    results.sort(key=lambda t: t.severity, reverse=True)
    return [t.to_dict() for t in results]


def get_highest_severity(techniques: list[dict]) -> int:
    """Return the maximum severity score from a list of technique dicts."""
    return max((t.get("severity", 0) for t in techniques), default=0)


def get_alert_level(techniques: list[dict]) -> str:
    """Convert numeric severity to a human-readable alert level."""
    sev = get_highest_severity(techniques)
    if sev >= 9:
        return "CRITICAL"
    if sev >= 7:
        return "HIGH"
    if sev >= 4:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_cases = [
        ("ListUsers",             None,           "iam"),
        ("ConsoleLogin",          "Failed",        "signin"),
        ("DeleteTrail",           None,            "cloudtrail"),
        ("GetObject",             None,            "s3"),
        ("CreateAccessKey",       None,            "iam"),
        ("ModifySnapshotAttribute", None,          "ec2"),
        ("TerminateInstances",    None,            "ec2"),
        ("PutBucketPolicy",       None,            "s3"),
    ]

    print("MITRE ATT&CK Mapping Test")
    print("=" * 60)
    for ev, err, svc in test_cases:
        techniques = map_to_mitre(ev, err, svc)
        level = get_alert_level(techniques)
        print(f"\n[{level}] {ev} (error={err}, service={svc})")
        for t in techniques:
            print(f"  {t['technique_id']:15s} {t['technique_name']:<50s} sev={t['severity']}")
