from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any
import json


SCHEMA_VERSION = "1.0.0"
PRODUCER_VERSION = "0.2.0"


class NodeType(str, Enum):
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"
    LLM = "LLM"
    AGENT = "AGENT"
    TOOL = "TOOL"
    KNOWLEDGE = "KNOWLEDGE"
    CODE = "CODE"
    CONDITION = "CONDITION"
    LOOP = "LOOP"
    STRUCTURAL = "STRUCTURAL"
    UNKNOWN = "UNKNOWN"


class Status(str, Enum):
    CONFIRMED = "CONFIRMED"
    OBSERVED = "OBSERVED"
    PROBABLE = "PROBABLE"
    CANDIDATE = "CANDIDATE"
    COVERAGE_GAP = "COVERAGE_GAP"
    MITIGATED = "MITIGATED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class VariableRef:
    producer_node_id: str
    variable_name: str
    consumer_node_id: str
    json_pointer: str
    consumer_field: str = ""
    resolution: str = "explicit"


@dataclass
class Edge:
    id: str
    source: str
    target: str
    source_handle: str | None = None
    target_handle: str | None = None
    source_index: int | None = None
    scope: str = "root"


@dataclass
class Node:
    id: str
    original_type: str
    type: str
    title: str
    json_pointer: str
    config: dict[str, Any] = field(default_factory=dict)
    container_id: str | None = None
    capabilities: list[str] = field(default_factory=list)
    tool_specs: list[dict[str, Any]] = field(default_factory=list)
    variable_refs: list[VariableRef] = field(default_factory=list)
    external: bool = False
    effectful: bool = False
    high_impact: bool = False


@dataclass
class Fact:
    id: str
    kind: str
    node_ids: list[str]
    evidence: list[str]
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    status: str
    severity: str
    confidence: float
    node_ids: list[str]
    evidence_refs: list[str]
    dsl_locations: list[str]
    message: str
    remediation: list[str]
    standards: list[str] = field(default_factory=list)
    missing_context: list[str] = field(default_factory=list)
    dynamic_test: str | None = None
    anchor_node_id: str | None = None
    control_domain: str = "general"
    report_group: str = "risk"
    related_rule_ids: list[str] = field(default_factory=list)
    path_variants: list[list[str]] = field(default_factory=list)
    instance_summaries: list[dict[str, Any]] = field(default_factory=list)
    waived: bool = False
    waiver_id: str | None = None


@dataclass
class WorkflowIR:
    workflow_id: str
    workflow_hash: str
    source_shape: str
    nodes: list[Node]
    edges: list[Edge]
    variable_refs: list[VariableRef]
    coverage_gaps: list[dict[str, Any]]
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    def node_map(self) -> dict[str, Node]:
        return {node.id: node for node in self.nodes}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, *parts: Any) -> str:
    raw = "|".join(str(part) for part in parts)
    return f"{prefix}-{sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    return value


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_jsonable(payload), ensure_ascii=False, indent=2), encoding="utf-8")
