#!/usr/bin/env python3
"""plan-policy-pack: versioned policy packs for InspectablePlans.

A policy pack is a versioned bundle of rules — security, privacy, org,
ethics — that a plan must satisfy before a human approves it. The pack
is content, not code: a team writes the rules it cares about in JSON,
versions the pack, and swaps it without touching any tool. This module
loads and validates packs, checks a plan against one, and runs a pack
over a corpus of known-good and known-bad plans to prove the pack
itself is sound — catching rules that never fire (dead rules) and
rules that fire on good plans (false positives).

It checks only. It never approves anything itself; the decision still
goes through plan-approve, and the blocking check at run time still
goes through plan-policy-check. This is the pack the checker reads.

Usage:
  python3 policy_pack.py examples/default-pack.json examples/plan.json
  python3 policy_pack.py examples/default-pack.json examples/plan.json --json
  python3 policy_pack.py --conformance examples/default-pack.json examples/conformance-corpus.json

Exit codes: 0 plan passes / conformance clean, 2 violations found /
conformance mismatch, 1 input error.
Standard library only.
"""
import argparse
import json
import sys

CATEGORIES = ("security", "privacy", "org", "ethics")
SEVERITIES = ("HIGH", "MEDIUM", "LOW")
MATCHER_TYPES = (
    "forbid_action",
    "forbid_target",
    "require_gate",
    "require_reason",
    "require_estimate",
    "require_field",
    "max_total_cost",
)


class PackError(Exception):
    """Raised when a pack or plan file cannot be read or understood."""


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def load_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise PackError(f"no such file: {path}")
    except json.JSONDecodeError as exc:
        raise PackError(f"{path} is not valid JSON: {exc}")
    if not isinstance(data, dict):
        raise PackError(f"{what} must be a JSON object")
    return data


def validate_matcher(match, rule_id):
    if not isinstance(match, dict):
        raise PackError(f"rule {rule_id}: 'match' must be an object")
    mtype = match.get("type")
    if mtype not in MATCHER_TYPES:
        raise PackError(
            f"rule {rule_id}: unknown matcher type {mtype!r}; "
            f"known types: {', '.join(MATCHER_TYPES)}")
    if mtype in ("forbid_action", "forbid_target"):
        key = "actions" if mtype == "forbid_action" else "targets"
        values = match.get(key)
        if (not isinstance(values, list) or not values
                or not all(isinstance(v, str) and v.strip() for v in values)):
            raise PackError(
                f"rule {rule_id}: matcher {mtype} needs a non-empty "
                f"'{key}' list of strings")
    if mtype == "require_field":
        field = match.get("field")
        if not isinstance(field, str) or not field.strip():
            raise PackError(
                f"rule {rule_id}: matcher require_field needs a non-empty "
                "'field' string")
    if mtype == "max_total_cost":
        limit = match.get("usd")
        if not _is_number(limit) or limit < 0:
            raise PackError(
                f"rule {rule_id}: matcher max_total_cost needs a "
                "'usd' number >= 0")


def load_pack(path):
    pack = load_json(path, "pack")
    if not isinstance(pack.get("name"), str) or not pack["name"].strip():
        raise PackError("pack must have a non-empty 'name'")
    version = pack.get("version")
    if not isinstance(version, int) or isinstance(version, bool) \
            or version < 1:
        raise PackError("pack must have a 'version' integer >= 1")
    rules = pack.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PackError("pack must have a non-empty 'rules' list")
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise PackError("each rule must be an object")
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid.strip():
            raise PackError("each rule must have a non-empty 'id'")
        if rid in seen:
            raise PackError(f"duplicate rule id: {rid}")
        seen.add(rid)
        if rule.get("category") not in CATEGORIES:
            raise PackError(
                f"rule {rid}: category must be one of "
                f"{', '.join(CATEGORIES)}")
        if rule.get("severity") not in SEVERITIES:
            raise PackError(
                f"rule {rid}: severity must be one of "
                f"{', '.join(SEVERITIES)}")
        if not isinstance(rule.get("description"), str) \
                or not rule["description"].strip():
            raise PackError(f"rule {rid}: needs a non-empty 'description'")
        validate_matcher(rule.get("match"), rid)
    return pack


def load_plan(path):
    plan = load_json(path, "plan")
    if not isinstance(plan.get("steps"), list) or not plan["steps"]:
        raise PackError("plan must have a non-empty 'steps' list")
    if not plan.get("goal"):
        raise PackError("plan must have a 'goal'")
    return plan


def _step_id(step, index):
    return step.get("id", f"step-{index + 1}")


def _contains(haystack, needle):
    return needle.lower() in (haystack or "").lower()


def _check_step_rule(rule, step, index):
    """Violations from one rule on one step, or [] if it passes."""
    match = rule["match"]
    mtype = match["type"]
    sid = _step_id(step, index)
    if mtype == "forbid_action":
        for action in match["actions"]:
            if _contains(step.get("action"), action):
                return [{
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "step": sid,
                    "message": f"Step {sid} does "
                               f"'{step.get('action')}', which the pack "
                               f"forbids (matches '{action}').",
                }]
        return []
    if mtype == "forbid_target":
        target = step.get("target")
        if target is None:
            return []
        for bad in match["targets"]:
            if _contains(target, bad):
                return [{
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "step": sid,
                    "message": f"Step {sid} targets '{target}', which "
                               f"the pack forbids (matches '{bad}').",
                }]
        return []
    if mtype == "require_gate":
        if step.get("irreversible") and not step.get("permission_gated"):
            return [{
                "rule_id": rule["id"],
                "category": rule["category"],
                "severity": rule["severity"],
                "step": sid,
                "message": f"Step {sid} cannot be undone and runs "
                           "without permission — the pack requires a "
                           "human gate on irreversible steps.",
            }]
        return []
    if mtype == "require_reason":
        if not (step.get("why") or "").strip():
            return [{
                "rule_id": rule["id"],
                "category": rule["category"],
                "severity": rule["severity"],
                "step": sid,
                "message": f"Step {sid} has no reason written down — "
                           "the pack requires one.",
            }]
        return []
    if mtype == "require_estimate":
        estimate = step.get("estimate") or {}
        if estimate.get("usd") is None and estimate.get("minutes") is None:
            return [{
                "rule_id": rule["id"],
                "category": rule["category"],
                "severity": rule["severity"],
                "step": sid,
                "message": f"Step {sid} has no cost or time estimate — "
                           "the pack requires one.",
            }]
        return []
    if mtype == "require_field":
        field = match["field"]
        value = step.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            return [{
                "rule_id": rule["id"],
                "category": rule["category"],
                "severity": rule["severity"],
                "step": sid,
                "message": f"Step {sid} is missing '{field}' — the pack "
                           "requires it on every step.",
            }]
        return []
    return []


def _plan_total_usd(plan):
    total = 0.0
    for step in plan["steps"]:
        estimate = step.get("estimate") or {}
        if estimate.get("usd") is not None:
            total += estimate["usd"]
    return total


def check_plan(plan, pack):
    """All violations when plan is checked against pack, in rule order."""
    violations = []
    for rule in pack["rules"]:
        if rule["match"]["type"] == "max_total_cost":
            total = _plan_total_usd(plan)
            limit = rule["match"]["usd"]
            if total > limit:
                violations.append({
                    "rule_id": rule["id"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "step": None,
                    "message": f"Plan total ${total:.2f} is over the pack "
                               f"limit of ${limit:.2f}.",
                })
            continue
        for index, step in enumerate(plan["steps"]):
            violations.extend(_check_step_rule(rule, step, index))
    return violations


def check(plan, pack):
    violations = check_plan(plan, pack)
    high = [v for v in violations if v["severity"] == "HIGH"]
    if high:
        verdict = ("FAIL — fix the HIGH violations before this plan "
                   "goes to a human.")
    elif violations:
        verdict = ("FAIL — nothing HIGH, but the violations below must "
                   "be fixed or waived first.")
    else:
        verdict = "PASS — the plan satisfies every rule in the pack."
    return {
        "plan_id": plan.get("id"),
        "pack": pack["name"],
        "pack_version": pack["version"],
        "violations": violations,
        "verdict": verdict,
    }


def load_corpus(path):
    corpus = load_json(path, "corpus")
    cases = corpus.get("cases")
    if not isinstance(cases, list) or not cases:
        raise PackError("corpus must have a non-empty 'cases' list")
    for case in cases:
        if not isinstance(case, dict):
            raise PackError("each corpus case must be an object")
        if not isinstance(case.get("plan"), dict):
            raise PackError("each corpus case needs a 'plan' object")
        if not isinstance(case.get("expect"), list) or not all(
                isinstance(r, str) for r in case["expect"]):
            raise PackError(
                "each corpus case needs an 'expect' list of rule ids")
        plan = case["plan"]
        if not isinstance(plan.get("steps"), list) or not plan["steps"]:
            raise PackError("each corpus plan needs a non-empty "
                            "'steps' list")
    return corpus


def conformance(pack, corpus):
    """Run the pack over the corpus; prove the pack itself is sound.

    A case passes when the rules that fire are exactly the ones it
    expects. A rule is dead when it never fires on any bad plan, and a
    false positive when it fires on a plan expected to pass clean.
    """
    results = []
    fired = {rule["id"]: 0 for rule in pack["rules"]}
    false_positives = set()
    for case in corpus["cases"]:
        actual = sorted({v["rule_id"] for v in check_plan(case["plan"], pack)})
        expected = sorted(set(case["expect"]))
        for rid in actual:
            fired[rid] += 1
        if not expected:
            false_positives.update(actual)
        results.append({
            "name": case.get("name", "(unnamed case)"),
            "expected": expected,
            "actual": actual,
            "passed": actual == expected,
        })
    dead = [rid for rid, count in fired.items() if count == 0]
    failed = [r for r in results if not r["passed"]]
    return {
        "pack": pack["name"],
        "pack_version": pack["version"],
        "cases": results,
        "cases_passed": len(results) - len(failed),
        "cases_total": len(results),
        "dead_rules": dead,
        "false_positive_rules": sorted(false_positives),
        "verdict": ("CLEAN — every case matched and every rule fired at "
                    "least once." if not failed and not dead and not
                    false_positives else
                    "REVIEW — the pack has cases that mismatch, dead "
                    "rules, or false positives; see below."),
    }


def render_markdown(result):
    out = ["# Policy check"]
    if result["plan_id"] is not None:
        out.append(f"Plan `{result['plan_id']}` against pack "
                   f"`{result['pack']}` v{result['pack_version']}")
    out.append("")
    out.append(f"**Verdict:** {result['verdict']}")
    out.append("")
    if result["violations"]:
        out.append("## Violations")
        out.append("")
        for v in result["violations"]:
            where = f"step {v['step']}" if v["step"] else "whole plan"
            out.append(f"- **{v['severity']}** `{v['rule_id']}` "
                       f"({v['category']}, {where}) — {v['message']}")
    else:
        out.append("No violations.")
    out.append("")
    return "\n".join(out)


def render_conformance_markdown(result):
    out = ["# Pack conformance"]
    out.append(f"Pack `{result['pack']}` v{result['pack_version']} — "
               f"{result['cases_passed']}/{result['cases_total']} cases "
               "matched")
    out.append("")
    out.append(f"**Verdict:** {result['verdict']}")
    out.append("")
    out.append("## Cases")
    out.append("")
    for case in result["cases"]:
        mark = "PASS" if case["passed"] else "FAIL"
        out.append(f"- **{mark}** {case['name']} — expected "
                   f"{case['expected'] or 'clean'}, got "
                   f"{case['actual'] or 'clean'}")
    out.append("")
    if result["dead_rules"]:
        out.append("## Dead rules (never fired on any bad plan)")
        out.append("")
        for rid in result["dead_rules"]:
            out.append(f"- `{rid}` — no corpus case exercises it; add a "
                       "case or drop the rule.")
        out.append("")
    if result["false_positive_rules"]:
        out.append("## False positives (fired on a plan expected clean)")
        out.append("")
        for rid in result["false_positive_rules"]:
            out.append(f"- `{rid}` — loosen the rule or fix the plan.")
        out.append("")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check an InspectablePlan against a versioned "
                    "policy pack, or run a pack over a conformance corpus.")
    parser.add_argument("pack", help="path to the policy pack JSON file")
    parser.add_argument("target", help="path to the plan JSON file, or the "
                        "conformance corpus with --conformance")
    parser.add_argument("--json", action="store_true",
                        help="print the result as JSON instead of Markdown")
    parser.add_argument("--conformance", action="store_true",
                        help="treat target as a conformance corpus")
    args = parser.parse_args(argv)
    try:
        pack = load_pack(args.pack)
        if args.conformance:
            corpus = load_corpus(args.target)
            result = conformance(pack, corpus)
            ok = (result["cases_passed"] == result["cases_total"]
                  and not result["dead_rules"]
                  and not result["false_positive_rules"])
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(render_conformance_markdown(result), end="")
            return 0 if ok else 2
        plan = load_plan(args.target)
        result = check(plan, pack)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(render_markdown(result), end="")
        return 0 if not result["violations"] else 2
    except PackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
