"""
scripts/simulate_attacks.py
---------------------------
Generates a synthetic CloudTrail CSV that mimics real attack patterns.
No AWS credentials required – useful for testing the full pipeline locally.

Attack scenarios:
  1. Permission Enumeration   (T1082 / T1526)
  2. Brute Force Login        (T1110.001)
  3. Privilege Escalation     (T1098.001, T1548)
  4. Defense Evasion          (T1562.008)
  5. Data Exfiltration        (T1530)
  6. Account Persistence      (T1136.003)
  7. Normal baseline traffic
"""

from __future__ import annotations

import csv
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUTPUT_FILE = "cloudtrail_logs_raw.csv"

ACCOUNT_ID = "619283293668"
REGION     = "us-east-1"
ATTACKER_IPS = ["198.51.100.10", "203.0.113.42", "185.220.101.5"]
NORMAL_IPS   = ["10.0.0.5", "10.0.1.22", "172.16.0.8"]

IAM_USER = {
    "type": "IAMUser",
    "principalId": "AIDAZAMBJEXSACP6TPZTA",
    "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/ml-ids-user",
    "accountId": ACCOUNT_ID,
    "accessKeyId": "AKIAZAMBJEXSFXEVH46R",
    "userName": "ml-ids-user",
}

ATTACKER_USER = {
    "type": "IAMUser",
    "principalId": "AIDATTACKERXYZ",
    "arn": f"arn:aws:iam::{ACCOUNT_ID}:user/compromised-user",
    "accountId": ACCOUNT_ID,
    "accessKeyId": "AKIACOMPROMISED",
    "userName": "compromised-user",
}


def _ts(offset_seconds: int = 0) -> str:
    t = datetime.now(timezone.utc) - timedelta(hours=2) + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def _row(
    event_name: str,
    event_source: str,
    source_ip: str,
    user_identity: dict,
    error_code: str = "",
    request_params: dict | None = None,
    response_elements: dict | None = None,
    offset: int = 0,
) -> dict:
    return {
        "eventVersion":      "1.11",
        "userIdentity":      json.dumps(user_identity),
        "eventTime":         _ts(offset),
        "eventSource":       event_source,
        "eventName":         event_name,
        "awsRegion":         REGION,
        "sourceIPAddress":   source_ip,
        "userAgent":         "python-boto3/1.40",
        "requestParameters": json.dumps(request_params or {}),
        "responseElements":  json.dumps(response_elements or {}),
        "requestID":         str(uuid.uuid4()),
        "eventID":           str(uuid.uuid4()),
        "readOnly":          "True",
        "eventType":         "AwsApiCall",
        "managementEvent":   "True",
        "recipientAccountId": ACCOUNT_ID,
        "eventCategory":     "Management",
        "tlsDetails":        json.dumps({"tlsVersion": "TLSv1.3"}),
        "additionalEventData": "",
        "sessionCredentialFromConsole": "",
        "errorCode":         error_code,
    }


def generate_events() -> list[dict]:
    events = []
    t = 0

    # ── Normal baseline (read-only ops) ──────────────────────────────────
    for i in range(40):
        ip = random.choice(NORMAL_IPS)
        ev = random.choice([
            ("ListBuckets",        "s3.amazonaws.com"),
            ("DescribeInstances",  "ec2.amazonaws.com"),
            ("ListFunctions20150331", "lambda.amazonaws.com"),
            ("GetCallerIdentity",  "sts.amazonaws.com"),
            ("ListUsers",          "iam.amazonaws.com"),
        ])
        events.append(_row(ev[0], ev[1], ip, IAM_USER, offset=t))
        t += random.randint(20, 90)

    # ── Attack 1: Permission enumeration ─────────────────────────────────
    for ev in ["ListUsers", "ListRoles", "ListPolicies", "ListGroups",
               "DescribeInstances", "ListBuckets", "ListFunctions20150331"]:
        service = "iam.amazonaws.com" if ev.startswith("List") and "Bucket" not in ev and "Function" not in ev else \
                  "ec2.amazonaws.com" if "Instance" in ev else \
                  "s3.amazonaws.com"  if "Bucket" in ev else "lambda.amazonaws.com"
        events.append(_row(ev, service, ATTACKER_IPS[0], ATTACKER_USER, offset=t))
        t += 3

    # ── Attack 2: Brute force console login ───────────────────────────────
    for i in range(8):
        events.append(_row(
            "ConsoleLogin", "signin.amazonaws.com", ATTACKER_IPS[1],
            {**ATTACKER_USER, "type": "Root"},
            error_code="Failed authentication",
            offset=t,
        ))
        t += 5

    # ── Attack 3: Privilege escalation ───────────────────────────────────
    events.append(_row("CreateAccessKey",   "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2
    events.append(_row("AttachUserPolicy",  "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2
    events.append(_row("PutUserPolicy",     "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2
    events.append(_row("PassRole",          "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2

    # ── Attack 4: Defense evasion ─────────────────────────────────────────
    events.append(_row("StopLogging",   "cloudtrail.amazonaws.com", ATTACKER_IPS[2], ATTACKER_USER, offset=t)); t += 1
    events.append(_row("DeleteTrail",   "cloudtrail.amazonaws.com", ATTACKER_IPS[2], ATTACKER_USER, offset=t)); t += 1
    events.append(_row("DeleteFlowLogs","ec2.amazonaws.com",        ATTACKER_IPS[2], ATTACKER_USER, offset=t)); t += 1

    # ── Attack 5: Data exfiltration ───────────────────────────────────────
    for _ in range(12):
        events.append(_row(
            "GetObject", "s3.amazonaws.com", ATTACKER_IPS[1], ATTACKER_USER,
            request_params={"bucketName": "prod-data", "key": f"sensitive/file{random.randint(1,99)}.csv"},
            offset=t,
        ))
        t += 2
    events.append(_row("PutBucketPolicy", "s3.amazonaws.com", ATTACKER_IPS[1], ATTACKER_USER, offset=t)); t += 2
    events.append(_row("ModifySnapshotAttribute", "ec2.amazonaws.com", ATTACKER_IPS[1], ATTACKER_USER, offset=t)); t += 2

    # ── Attack 6: Persistence ─────────────────────────────────────────────
    events.append(_row("CreateUser",   "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2
    events.append(_row("CreateRole",   "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2
    events.append(_row("AttachRolePolicy", "iam.amazonaws.com", ATTACKER_IPS[0], ATTACKER_USER, offset=t)); t += 2

    # ── More normal traffic to balance ───────────────────────────────────
    for i in range(20):
        events.append(_row(
            random.choice(["GetObject", "DescribeInstances", "ListBuckets"]),
            random.choice(["s3.amazonaws.com", "ec2.amazonaws.com"]),
            random.choice(NORMAL_IPS), IAM_USER, offset=t,
        ))
        t += random.randint(10, 60)

    random.shuffle(events)
    return events


FIELDNAMES = [
    "eventVersion", "userIdentity", "eventTime", "eventSource", "eventName",
    "awsRegion", "sourceIPAddress", "userAgent", "requestParameters",
    "responseElements", "requestID", "eventID", "readOnly", "eventType",
    "managementEvent", "recipientAccountId", "eventCategory", "tlsDetails",
    "additionalEventData", "sessionCredentialFromConsole", "errorCode",
]


def main(output: str = OUTPUT_FILE) -> None:
    events = generate_events()
    events.sort(key=lambda e: e["eventTime"], reverse=True)

    path = Path(output)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(events)

    print(f"✓  {len(events)} synthetic CloudTrail events written → {path}")
    print(f"   (includes {sum(1 for e in events if e['errorCode'])} error events)")


if __name__ == "__main__":
    main()
