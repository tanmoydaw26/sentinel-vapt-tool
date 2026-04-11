from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any
from datetime import datetime

@dataclass
class Evidence:
    type: str
    description: str
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Vulnerability:
    title: str
    description: str
    severity: str
    cvss_score: float
    cwe: str
    owasp: str
    category: str
    affected_target: str
    endpoint: str
    parameter: str = ""
    poc: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    confidence: float = 0.8
    correlated_risk: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self):
        data = asdict(self)
        data['evidence'] = [asdict(e) for e in self.evidence]
        return data

@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: List[Vulnerability] = field(default_factory=list)
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    directories: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    logs: List[Dict[str, Any]] = field(default_factory=list)

    def add_finding(self, finding: Vulnerability):
        self.findings.append(finding)

    def to_dict(self):
        return {
            'target': self.target,
            'started_at': self.started_at,
            'finished_at': self.finished_at,
            'findings': [f.to_dict() for f in self.findings],
            'open_ports': self.open_ports,
            'subdomains': self.subdomains,
            'directories': self.directories,
            'metadata': self.metadata,
            'logs': self.logs
        }
