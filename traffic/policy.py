"""Pre-transmission policy evaluation with a complete decision trail.

A rule matches only when every condition it names is supported by evidence. A
missing process, destination, field, or body means the rule does not match and
the decision says which evidence was missing. Nothing is inferred to make a
rule fire.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

from .util import as_bytes, as_int, cidr_match, glob_match, sha256_file


ACTIONS = ("allow", "drop", "audit")


@dataclass
class Policy:
    path: str
    sha256: str
    name: str
    default: str
    rules: list[dict]
    raw: dict
    notes: list[str] = field(default_factory=list)

    @property
    def needs_fields(self):
        return any("field" in (rule.get("match") or {}) for rule in self.rules)

    @property
    def needs_destination(self):
        return any("destination" in (rule.get("match") or {}) for rule in self.rules)

    def summary(self):
        return {
            "path": self.path,
            "sha256": self.sha256,
            "name": self.name,
            "default": self.default,
            "rules": len(self.rules),
            "needs_fields": self.needs_fields,
            "needs_destination": self.needs_destination,
            "notes": self.notes,
        }


def _require_mapping(value, what):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object")
    return value


def load_policy(path):
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("policy must be a JSON object")
    default = str(raw.get("default", "allow")).lower()
    if default not in ACTIONS:
        raise ValueError(f"policy default must be one of {ACTIONS}")
    rules = raw.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("policy rules must be a list")
    normalised = []
    seen = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"rule {index} must be an object")
        rule_id = str(rule.get("id") or f"rule-{index + 1}")
        if rule_id in seen:
            raise ValueError(f"duplicate rule id {rule_id!r}")
        seen.add(rule_id)
        action = str(rule.get("action", "allow")).lower()
        if action not in ACTIONS:
            raise ValueError(f"rule {rule_id}: action must be one of {ACTIONS}")
        match = _require_mapping(rule.get("match"), f"rule {rule_id} match")
        if not match:
            raise ValueError(f"rule {rule_id}: an empty match would affect unrelated traffic")
        if "process" in match:
            _require_mapping(match["process"], f"rule {rule_id} process")
        if "destination" in match:
            _require_mapping(match["destination"], f"rule {rule_id} destination")
        if "type" in match:
            _require_mapping(match["type"], f"rule {rule_id} type")
        if "field" in match:
            fields = match["field"]
            if not isinstance(fields, list) or not fields:
                raise ValueError(f"rule {rule_id}: field must be a non-empty list")
            for condition in fields:
                _require_mapping(condition, f"rule {rule_id} field condition")
                if not any(key in condition for key in ("name", "offset")):
                    raise ValueError(f"rule {rule_id}: a field condition needs name or offset")
        if "raw" in match:
            raw_match = _require_mapping(match["raw"], f"rule {rule_id} raw")
            if "match_hex" not in raw_match:
                raise ValueError(f"rule {rule_id}: raw needs match_hex")
            if as_bytes(raw_match["match_hex"]) is None:
                raise ValueError(f"rule {rule_id}: raw match_hex is not valid hex")
        normalised.append({
            "id": rule_id,
            "action": action,
            "description": rule.get("description", ""),
            "match": match,
            "raw": rule,
        })
    notes = []
    if not normalised:
        notes.append("policy has no rules; only the default action applies")
    return Policy(
        path=str(path),
        sha256=sha256_file(path),
        name=str(raw.get("name") or path.stem),
        default=default,
        rules=normalised,
        raw=raw,
        notes=notes,
    )


def _message_view(message):
    process = message.get("process") or {}
    transport = message.get("transport") or {}
    body_message = message.get("message") or {}
    destination = transport.get("destination") or {}
    body = as_bytes(body_message.get("raw_bytes_hex"))
    fields = body_message.get("fields") or []
    protocols = []
    for value in (transport.get("protocol"), body_message.get("protocol")):
        if value and value not in protocols:
            protocols.append(value)
    return {
        "process": process,
        "protocols": protocols,
        "destination": destination,
        "type": body_message.get("type") or {},
        "body": body,
        "fields": fields,
        "size": len(body) if body is not None else None,
        "decode_status": body_message.get("decode_status"),
        "message_id": message.get("message_id"),
    }


def _missing(dimension, detail):
    return {"dimension": dimension, "detail": detail}


def _match_process(condition, view, missing):
    process = view["process"] or {}
    for key in ("name", "path"):
        if key not in condition:
            continue
        value = process.get(key)
        pattern = condition[key]
        if value is None:
            missing.append(_missing("process." + key, f"process {key} is missing"))
            return False
        if isinstance(pattern, list):
            if not any(glob_match(value, item) for item in pattern):
                return False
        elif not glob_match(value, pattern):
            return False
    for key in ("pid", "build_timestamp", "module_base"):
        if key not in condition:
            continue
        value = process.get(key)
        if value is None and key == "build_timestamp":
            value = (process.get("build") or {}).get("pe_timestamp")
        expected = as_int(condition[key])
        if value is None:
            missing.append(_missing("process." + key, f"process {key} is missing"))
            return False
        if as_int(value) != expected:
            return False
    return True


def _match_destination(condition, view, missing):
    destination = view["destination"] or {}
    for key in ("host", "path_prefix"):
        if key not in condition:
            continue
        value = destination.get(key)
        if value is None:
            missing.append(_missing("destination." + key, f"destination {key} is missing"))
            return False
        pattern = condition[key]
        if key == "path_prefix":
            if not str(value).startswith(str(pattern)):
                return False
        elif isinstance(pattern, list):
            if not any(glob_match(value, item) for item in pattern):
                return False
        elif not glob_match(value, pattern):
            return False
    if "ip" in condition:
        value = destination.get("ip")
        if value is None:
            missing.append(_missing("destination.ip", "destination IP is missing"))
            return False
        if not cidr_match(value, condition["ip"]):
            return False
    if "cidr" in condition:
        value = destination.get("ip")
        if value is None:
            missing.append(_missing("destination.ip", "destination IP is missing"))
            return False
        if not cidr_match(value, condition["cidr"]):
            return False
    if "port" in condition:
        value = as_int(destination.get("port"))
        if value is None:
            missing.append(_missing("destination.port", "destination port is missing"))
            return False
        expected = condition["port"]
        allowed = expected if isinstance(expected, list) else [expected]
        if value not in [as_int(item) for item in allowed]:
            return False
    return True


def _match_type(condition, view, missing):
    message_type = view["type"] or {}
    if "opcode" in condition:
        value = as_int(message_type.get("opcode"))
        if value is None:
            missing.append(_missing("type.opcode", "decoded opcode is missing"))
            return False
        expected = condition["opcode"]
        allowed = expected if isinstance(expected, list) else [expected]
        if value not in [as_int(item) for item in allowed]:
            return False
    if "name" in condition:
        value = message_type.get("name")
        if value is None:
            missing.append(_missing("type.name", "message type name is unknown"))
            return False
        pattern = condition["name"]
        if isinstance(pattern, list):
            if not any(glob_match(value, item) for item in pattern):
                return False
        elif not glob_match(value, pattern):
            return False
    if "confidence" in condition:
        value = message_type.get("confidence")
        if value is None:
            missing.append(_missing("type.confidence", "type confidence is missing"))
            return False
        allowed = condition["confidence"]
        allowed = allowed if isinstance(allowed, list) else [allowed]
        if value not in allowed:
            return False
    return True


def _find_field(view, condition):
    for field in view["fields"]:
        if "name" in condition and field.get("name") != condition["name"]:
            continue
        if "offset" in condition and field.get("offset") != as_int(condition["offset"]):
            continue
        if "size" in condition and field.get("size") != as_int(condition["size"]):
            continue
        if field.get("value") is None and "equals" in condition:
            return field, False
        return field, True
    return None, False


def _compare_field(field, condition):
    value = field.get("value")
    if "equals" in condition:
        expected = condition["equals"]
        if isinstance(value, int):
            expected = as_int(expected)
            if expected is None:
                return False
            return value == expected
        return str(value) == str(expected)
    if "not_equals" in condition:
        expected = condition["not_equals"]
        if isinstance(value, int):
            expected = as_int(expected)
        return value != expected
    if "in" in condition:
        values = condition["in"]
        if not isinstance(values, list):
            return False
        if isinstance(value, int):
            return value in [as_int(item) for item in values]
        return value in values
    if "mask" in condition:
        mask = as_int(condition["mask"])
        expected = as_int(condition.get("value", 0))
        if not isinstance(value, int) or mask is None or expected is None:
            return False
        return (value & mask) == expected
    if "min" in condition or "max" in condition:
        number = as_int(value)
        if number is None:
            return False
        if "min" in condition and number < as_int(condition["min"]):
            return False
        if "max" in condition and number > as_int(condition["max"]):
            return False
        return True
    if "hex_prefix" in condition:
        raw = str(field.get("raw_hex") or "")
        return raw.startswith(str(condition["hex_prefix"]).lower())
    return True


def _match_field(conditions, view, missing):
    for condition in conditions:
        field, has_value = _find_field(view, condition)
        if field is None:
            missing.append(_missing("field", f"field condition {condition} did not find a decoded field"))
            return False
        if not has_value:
            missing.append(_missing("field", f"field {field.get('name') or condition} has no value"))
            return False
        if not _compare_field(field, condition):
            return False
    return True


def _match_raw(condition, view, missing):
    body = view["body"]
    if body is None:
        missing.append(_missing("raw", "application body is missing"))
        return False
    offset = as_int(condition.get("offset"), 0)
    match = as_bytes(condition["match_hex"])
    if offset is None or offset < 0 or match is None:
        return False
    chunk = body[offset:offset + len(match)]
    if len(chunk) != len(match):
        missing.append(_missing("raw", "application body is shorter than the requested raw match"))
        return False
    if "match_hex" in condition and chunk != match:
        return False
    return True


def _match_rule(rule, view):
    match = rule["match"]
    missing = []
    checks = []
    dimensions = (
        ("process", _match_process),
        ("destination", _match_destination),
        ("type", _match_type),
    )
    for name, function in dimensions:
        if name not in match:
            continue
        before = len(missing)
        matched = function(match[name], view, missing)
        checks.append({
            "dimension": name,
            "condition": match[name],
            "matched": matched,
            "missing_evidence": missing[before:],
        })
        if not matched:
            return False, checks, missing
    if "protocol" in match:
        expected = match["protocol"]
        expected = expected if isinstance(expected, list) else [expected]
        matched = any(protocol in expected for protocol in view["protocols"])
        checks.append({
            "dimension": "protocol",
            "condition": expected,
            "matched": matched,
            "observed": view["protocols"],
        })
        if not matched:
            return False, checks, missing
    if "field" in match:
        before = len(missing)
        matched = _match_field(match["field"], view, missing)
        checks.append({
            "dimension": "field",
            "condition": match["field"],
            "matched": matched,
            "missing_evidence": missing[before:],
        })
        if not matched:
            return False, checks, missing
    if "raw" in match:
        before = len(missing)
        matched = _match_raw(match["raw"], view, missing)
        checks.append({
            "dimension": "raw",
            "condition": match["raw"],
            "matched": matched,
            "missing_evidence": missing[before:],
        })
        if not matched:
            return False, checks, missing
    if "size" in match:
        condition = match["size"]
        size = view["size"]
        if size is None:
            missing.append(_missing("size", "application body size is missing"))
            checks.append({"dimension": "size", "condition": condition, "matched": False,
                           "missing_evidence": missing[-1:]})
            return False, checks, missing
        minimum = as_int(condition.get("min"), 0)
        maximum = as_int(condition.get("max"), 1 << 62)
        matched = minimum <= size <= maximum
        checks.append({
            "dimension": "size",
            "condition": condition,
            "observed": size,
            "matched": matched,
        })
        if not matched:
            return False, checks, missing
    return True, checks, missing


def evaluate(policy, message, context=None):
    """Return a decision record for one message; never throws for missing evidence."""
    view = _message_view(message)
    evaluated = []
    for rule in policy.rules:
        matched, checks, missing = _match_rule(rule, view)
        evaluated.append({
            "rule_id": rule["id"],
            "action": rule["action"],
            "matched": matched,
            "checks": checks,
            "missing_evidence": missing,
        })
        if matched:
            return {
                "policy": {"name": policy.name, "sha256": policy.sha256, "default": policy.default},
                "message_id": view["message_id"],
                "matched": True,
                "rule_id": rule["id"],
                "action": rule["action"],
                "reason": "first matching rule",
                "description": rule.get("description", ""),
                "checks": checks,
                "missing_evidence": missing,
                "evaluated_rules": evaluated,
            }
    reason = "default action"
    if any(item["missing_evidence"] for item in evaluated):
        reason = "no rule matched with complete evidence; default action"
    return {
        "policy": {"name": policy.name, "sha256": policy.sha256, "default": policy.default},
        "message_id": view["message_id"],
        "matched": False,
        "rule_id": None,
        "action": policy.default,
        "reason": reason,
        "checks": [],
        "missing_evidence": [],
        "evaluated_rules": evaluated,
    }


def _kfilter_action(action):
    return "audit" if action == "audit" else action


def policy_to_kfilter(policy):
    """Emit the subset of this policy that kfilter's Linux message layer can enforce.

    kfilter sees ciphertext at the syscall boundary. A decoded game opcode or a
    field cannot be translated into a kernel match unless the policy supplies an
    explicit raw byte match. Unsupported dimensions are emitted as comments so a
    reviewer can see what did not transfer.
    """
    lines = [
        "# generated by client-control traffic/policy.py",
        f"# policy: {policy.name} sha256={policy.sha256}",
        "# kfilter message rules need a 'protect' entry for each target image.",
    ]
    protected = set()
    for rule in policy.rules:
        match = rule["match"]
        process = match.get("process") or {}
        target = process.get("name") or process.get("path")
        if target and target not in protected:
            protected.add(target)
            lines.append(f"protect {target}")
    lines.append("")
    for rule in policy.rules:
        match = rule["match"]
        unsupported = []
        fields = [f"{_kfilter_action(rule['action'])}|message"]
        process = match.get("process") or {}
        if process.get("name"):
            fields.append(f"image={process['name']}")
        elif process.get("path"):
            unsupported.append("process.path cannot be expressed as image= (use protect)")
        destination = match.get("destination") or {}
        if destination.get("ip") or destination.get("cidr"):
            fields.append(f"ip={destination.get('ip') or destination.get('cidr')}")
        if destination.get("port") is not None:
            fields.append(f"port={destination['port']}")
        if destination.get("host"):
            unsupported.append("destination.host needs name resolution; not emitted")
        if destination.get("path_prefix"):
            unsupported.append("destination.path_prefix is application-level; not emitted")
        protocol = match.get("protocol")
        if isinstance(protocol, str) and protocol in ("tcp", "udp"):
            fields.append(f"proto={protocol}")
        elif protocol:
            unsupported.append("protocol is not tcp/udp")
        if "size" in match:
            condition = match["size"]
            minimum = as_int(condition.get("min"), 0)
            maximum = as_int(condition.get("max"), 2**31 - 1)
            fields.append(f"size={minimum}-{maximum}")
        raw = match.get("raw") or {}
        if raw.get("match_hex"):
            offset = as_int(raw.get("offset"), 0)
            fields.append(f"match={raw['match_hex']}@{offset}")
        if "type" in match:
            unsupported.append("type/opcode is encoded in the application body; not emitted")
        if "field" in match:
            unsupported.append("decoded field conditions are not expressible in kfilter")
        if unsupported:
            lines.append(f"# rule {rule['id']} not fully translated: {'; '.join(unsupported)}")
            # Emit the expressible core only when it still constrains the traffic.
            if not any(item.startswith(("ip=", "port=", "proto=", "size=", "match=")) for item in fields):
                continue
        fields.append(f"risk=client-control-{rule['id']}")
        lines.append("|".join(fields))
    lines.append(f"message-default {'deny' if policy.default == 'drop' else 'allow'}")
    return "\n".join(lines) + "\n"
