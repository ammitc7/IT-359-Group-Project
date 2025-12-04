from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import re
import pathlib
import yaml


# -----------------------------
# Data models
# -----------------------------

@dataclass
class PortFinding:
    host: str
    hostname: Optional[str]
    port: int
    protocol: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]

@dataclass
class VulnSignature:
    id: str
    name: str
    severity: str
    affected_ports: List[int]
    affected_services: List[str]
    product_regex: Optional[re.Pattern]
    version_regex: Optional[re.Pattern]
    description: str
    references: List[str]

@dataclass
class CorrelatedVulnerability:
    host: str
    hostname: Optional[str]
    port: int
    protocol: str
    service: Optional[str]
    product: Optional[str]
    version: Optional[str]
    vuln_id: str
    vuln_name: str
    severity: str
    description: str
    references: List[str]
    match_reason: str


# -----------------------------
# Loading signatures
# -----------------------------

def _compile_regex(pattern: Optional[str]) -> Optional[re.Pattern]:
    if not pattern:
        return None
    # case-insensitive, "search" style
    return re.compile(pattern, re.IGNORECASE)


def load_vuln_signatures(path: str | pathlib.Path) -> List[VulnSignature]:
    """
    Load vulnerability signatures from a YAML file.

    YAML format (per entry):

    - id: CVE-XXXX-YYYY
      name: Some vuln
      severity: critical|high|medium|low|info
      affected:
        ports: [80, 443]
        services: ["http", "https"]
        product_regex: "nginx"
        version_regex: "1\\.1[0-7]\\..*"
      description: ...
      references:
        - "https://example.com"
    """
    path = pathlib.Path(path)
    with path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or []

    signatures: List[VulnSignature] = []

    for entry in raw:
        affected = entry.get("affected", {})
        ports = affected.get("ports") or []
        services = [s.lower() for s in (affected.get("services") or [])]

        signatures.append(
            VulnSignature(
                id=entry.get("id", "UNKNOWN"),
                name=entry.get("name", "Unnamed vulnerability"),
                severity=entry.get("severity", "unknown").lower(),
                affected_ports=ports,
                affected_services=services,
                product_regex=_compile_regex(affected.get("product_regex")),
                version_regex=_compile_regex(affected.get("version_regex")),
                description=entry.get("description", ""),
                references=entry.get("references") or [],
            )
        )

    return signatures


# -----------------------------
# Correlation logic
# -----------------------------

def _match_signature_to_finding(sig: VulnSignature, finding: PortFinding) -> Optional[str]:
    """
    Return a human-readable reason string if the signature matches
    this finding; otherwise return None.
    """

    reasons = []

    # Port match (if any ports defined)
    if sig.affected_ports:
        if finding.port not in sig.affected_ports:
            return None
        reasons.append(f"port {finding.port} in {sig.affected_ports}")

    # Service match (if any services defined)
    if sig.affected_services:
        service = (finding.service or "").lower()
        if service not in sig.affected_services:
            return None
        reasons.append(f"service '{service}' in {sig.affected_services}")

    # Product regex (optional)
    if sig.product_regex is not None:
        product = finding.product or ""
        if not sig.product_regex.search(product):
            return None
        reasons.append(f"product '{product}' matches /{sig.product_regex.pattern}/i")

    # Version regex (optional)
    if sig.version_regex is not None:
        version = finding.version or ""
        if not sig.version_regex.search(version):
            return None
        reasons.append(f"version '{version}' matches /{sig.version_regex.pattern}/i")

    if not reasons:
        # If signature has no constraints at all, treat as non-match to avoid noise.
        return None

    return "; ".join(reasons)


def correlate_vulnerabilities(
    findings: List[PortFinding],
    signatures: List[VulnSignature],
) -> List[CorrelatedVulnerability]:
    """
    Given a list of PortFinding objects and vuln signatures, return
    a list of correlated vulnerabilities.
    """
    results: List[CorrelatedVulnerability] = []

    for f in findings:
        for sig in signatures:
            reason = _match_signature_to_finding(sig, f)
            if reason is None:
                continue

            results.append(
                CorrelatedVulnerability(
                    host=f.host,
                    hostname=f.hostname,
                    port=f.port,
                    protocol=f.protocol,
                    service=f.service,
                    product=f.product,
                    version=f.version,
                    vuln_id=sig.id,
                    vuln_name=sig.name,
                    severity=sig.severity,
                    description=sig.description,
                    references=sig.references,
                    match_reason=reason,
                )
            )

    return results


# -----------------------------
# Helper: build findings from dicts (if your parser uses dicts)
# -----------------------------

def findings_from_dicts(rows: List[Dict[str, Any]]) -> List[PortFinding]:
    """
    Convenience helper if your nmap parser returns dicts instead of
    PortFinding instances.

    Expected keys in each dict:
      host, hostname, port, protocol, service, product, version
    """
    result: List[PortFinding] = []

    for row in rows:
        result.append(
            PortFinding(
                host=str(row.get("host", "")),
                hostname=row.get("hostname"),
                port=int(row.get("port")),
                protocol=str(row.get("protocol", "tcp")),
                service=row.get("service"),
                product=row.get("product"),
                version=row.get("version"),
            )
        )

    return result
