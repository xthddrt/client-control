"""Ordered, default-allow policy decisions for plaintext messages."""

import fnmatch
import hashlib
import ipaddress
import json
from pathlib import Path


SELECTORS = {"process", "protocol", "destination", "type", "field", "direction"}


def _text(value):
    return str(value).lower() if value is not None else None


def _same(actual, expected):
    if actual is None:
        return False
    if isinstance(expected, str) and isinstance(actual, int):
        try:
            return actual == int(expected, 0)
        except ValueError:
            pass
    return actual == expected or _text(actual) == _text(expected)


def _glob(actual, pattern, process=False):
    if actual is None:
        return False
    actual = str(actual)
    pattern = str(pattern)
    if process:
        actual = actual.replace("\\", "/").lower()
        pattern = pattern.replace("\\", "/").lower()
        if "/" not in pattern:
            actual = actual.rsplit("/", 1)[-1]
    return fnmatch.fnmatchcase(actual, pattern)


def _field(message, path):
    value = message.get("fields", {})
    for part in str(path).split("."):
        if isinstance(value, dict):
            if part not in value:
                return None
            value = value[part]
        elif isinstance(value, list) and part.isdecimal() and int(part) < len(value):
            value = value[int(part)]
        else:
            return None
        if isinstance(value, dict) and set(value) >= {"value", "offset"}:
            value = value["value"]
    return value


def _destination(message, expected):
    destination = message.get("destination")
    if destination is None:
        return False
    if isinstance(expected, str):
        if not isinstance(destination, dict):
            return _glob(destination, expected)
        host = destination.get("host")
        return _glob(host or destination.get("ip") or destination.get("address"), expected)
    if not isinstance(expected, dict):
        return False
    for key, wanted in expected.items():
        if key == "network":
            address = destination.get("ip") or destination.get("address")
            try:
                if address is None or ipaddress.ip_address(address) not in ipaddress.ip_network(wanted):
                    return False
            except ValueError:
                return False
        elif key == "port":
            try:
                if destination.get("port") != int(wanted):
                    return False
            except (TypeError, ValueError):
                return False
        elif key in ("host", "ip", "address"):
            if not _glob(destination.get(key) or destination.get("address"), wanted):
                return False
        else:
            return False
    return True


class Policy:
    def __init__(self, document=None, source=None):
        self.document = document or {"version": 1, "mode": "enforce", "default": "allow", "rules": []}
        self.source = str(source) if source is not None else None
        self.validate()
        self.canonical = json.dumps(self.document, sort_keys=True, separators=(",", ":"))
        self.sha256 = hashlib.sha256(self.canonical.encode()).hexdigest()

    @classmethod
    def load(cls, path):
        if path is None:
            return cls()
        path = Path(path)
        return cls(json.loads(path.read_text(encoding="utf-8")), path)

    def validate(self):
        if not isinstance(self.document, dict) or self.document.get("version") != 1:
            raise ValueError("Traffic policy must be an object with version 1.")
        if self.document.get("mode", "enforce") not in ("audit", "enforce"):
            raise ValueError("Traffic policy mode must be audit or enforce.")
        if self.document.get("default", "allow") not in ("allow", "drop"):
            raise ValueError("Traffic policy default must be allow or drop.")
        rules = self.document.get("rules")
        if not isinstance(rules, list):
            raise ValueError("Traffic policy rules must be a list.")
        identifiers = set()
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict) or rule.get("action") not in ("allow", "audit", "drop"):
                raise ValueError(f"Rule {index + 1} needs action allow, audit, or drop.")
            unknown = set(rule) - SELECTORS - {"id", "action", "reason"}
            if unknown:
                raise ValueError(f"Rule {index + 1} has unknown selectors: {sorted(unknown)}")
            identifier = rule.get("id", f"rule-{index + 1}")
            if not isinstance(identifier, str) or not identifier or identifier in identifiers:
                raise ValueError(f"Rule {index + 1} needs a unique nonempty string id.")
            identifiers.add(identifier)
            field = rule.get("field")
            if field is not None and (
                not isinstance(field, dict)
                or not isinstance(field.get("name"), str)
                or not field["name"]
                or "equals" not in field
                or set(field) != {"name", "equals"}
            ):
                raise ValueError(f"Rule {identifier} field must contain only name and equals.")
            destination = rule.get("destination")
            if destination is not None and not isinstance(destination, (str, dict)):
                raise ValueError(f"Rule {identifier} destination must be a host glob or an object.")
            if isinstance(destination, dict):
                if not destination or set(destination) - {"host", "ip", "address", "port", "network"}:
                    raise ValueError(f"Rule {identifier} has an empty or unknown destination selector.")
                if "port" in destination:
                    try:
                        port = int(destination["port"])
                    except (TypeError, ValueError) as error:
                        raise ValueError(f"Rule {identifier} destination port is not numeric.") from error
                    if not 0 <= port <= 65535:
                        raise ValueError(f"Rule {identifier} destination port must be 0-65535.")
                if "network" in destination:
                    try:
                        ipaddress.ip_network(destination["network"])
                    except (TypeError, ValueError) as error:
                        raise ValueError(f"Rule {identifier} destination network is invalid.") from error

    def matches(self, rule, message):
        process = message.get("process")
        processes = [process]
        if isinstance(process, dict):
            processes = [process.get("path"), process.get("name")]
        if "process" in rule and not any(_glob(candidate, rule["process"], process=True) for candidate in processes):
            return False
        for key, message_key in (("protocol", "protocol"), ("type", "type"), ("direction", "direction")):
            if key in rule and not _glob(message.get(message_key), rule[key]):
                return False
        if "destination" in rule and not _destination(message, rule["destination"]):
            return False
        if "field" in rule:
            field = rule["field"]
            if not _same(_field(message, field["name"]), field["equals"]):
                return False
        return True

    def decide(self, message):
        mode = self.document.get("mode", "enforce")
        for index, rule in enumerate(self.document["rules"]):
            if not self.matches(rule, message):
                continue
            action = rule["action"]
            effective = "would_drop" if action == "drop" and mode == "audit" else action
            return {
                "action": action,
                "effective_action": effective,
                "forward": effective != "drop",
                "matched": True,
                "rule_id": rule.get("id", f"rule-{index + 1}"),
                "rule_index": index,
                "reason": rule.get("reason"),
                "mode": mode,
                "policy_sha256": self.sha256,
            }
        action = self.document.get("default", "allow")
        effective = "would_drop" if action == "drop" and mode == "audit" else action
        return {
            "action": action,
            "effective_action": effective,
            "forward": effective != "drop",
            "matched": False,
            "rule_id": None,
            "rule_index": None,
            "reason": "default",
            "mode": mode,
            "policy_sha256": self.sha256,
        }


def self_test():
    policy = Policy({
        "version": 1,
        "rules": [
            {"id": "audit-family", "action": "audit", "process": "*.exe"},
            {"id": "drop-pickup", "action": "drop", "protocol": "maple", "type": "0x32b",
             "field": {"name": "drop_object_id", "equals": "0x143ff"}},
        ],
    })
    message = {
        "process": {"name": "MapleStory.exe"}, "protocol": "maple", "type": "0x32b",
        "fields": {"drop_object_id": 0x143FF}, "destination": None,
    }
    assert policy.decide(message)["rule_id"] == "audit-family"
    policy.document["rules"].pop(0)
    policy = Policy(policy.document)
    assert policy.decide(message)["effective_action"] == "drop"
    message["fields"]["drop_object_id"] += 1
    assert policy.decide(message)["action"] == "allow"
    message["fields"]["drop_object_id"] -= 1
    policy.document["mode"] = "audit"
    policy = Policy(policy.document)
    assert policy.decide(message)["forward"] and policy.decide(message)["effective_action"] == "would_drop"
    destination = Policy({"version": 1, "rules": [{
        "id": "ngs", "action": "drop", "protocol": "https",
        "destination": {"host": "x-*.ngs.nexon.com", "port": 443},
    }]})
    message.update({"protocol": "https", "destination": {"host": "x-init.ngs.nexon.com", "port": 443}})
    assert destination.decide(message)["rule_id"] == "ngs"
    message["destination"] = None
    assert destination.decide(message)["action"] == "allow"
    try:
        Policy({"version": 1, "rules": [{"action": "drop", "destination": {"network": "invalid"}}]})
    except ValueError:
        pass
    else:
        raise AssertionError("Invalid destination network was accepted")
    process_rule = Policy({"version": 1, "rules": [{"action": "audit", "process": "MapleStory.exe"}]})
    message["process"] = {"path": "/opt/wine/bin/wine64-preloader", "name": "MapleStory.exe"}
    assert process_rule.decide(message)["matched"]
    print("PASS: ordered process/protocol/destination/type/field policy and safe defaults.")


if __name__ == "__main__":
    self_test()
