#!/usr/bin/env python3
"""Score one team's submission for the Insecure Architecture challenge.

The submission is treated purely as data: files are read and parsed, never
executed. Python sources are compiled to check syntax, not run.

Usage:
    python score.py --repo <path-to-submission> --team <name> [--sha <commit>]
                    [--out result.json] [--summary summary.md]
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

FIX_POINTS = 10
CLASS_POINTS = 5
BROKEN_PENALTY = 20

AREAS = {
    1: "Identity",
    2: "Data exposure",
    3: "Secrets",
    4: "Supply chain",
    5: "Release gate",
    6: "Network",
    7: "Detection",
    8: "Recovery",
}

# Accepted classifications per check.
EXPECTED_TYPES = {
    1: {"constraint"},
    2: {"constraint"},
    3: {"constraint"},
    4: {"sensor", "constraint"},
    5: {"actuation", "constraint"},
    6: {"constraint"},
    7: {"sensor"},
    8: {"actuation"},
}

# Keywords that tie a DECISION.md row to a check. Order matters: most specific first.
ROW_KEYWORDS = [
    (8, r"rollback|roll back|rollout|revert|revisionhistory|revision history|recreate|recover|response path"),
    (7, r"telemetry|cloudtrail|guardduty|enable_logging|audit log|monitor|detect|visibility|observab"),
    (6, r"egress|outbound|build[- ]?agent|runner|bootstrap|65535|plat-412"),
    (5, r"\bgate\b|exit-code|exit code|soft-fail|soft fail|non-?blocking|security-scan|security scan|trivy|checkov|scan"),
    (3, r"secret|password|credential|database_url|connection string|\bvars\b|vars\.|registry_password|plain ?text|hard[- ]?coded"),
    (4, r"depend|pyyaml|requests|requirements|extra-index|index-url|mirror|package|library|checksum|\badd\b|dockerfile|fonts|supply|cve|vulnerab"),
    (1, r"\biam\b|notaction|not action|wildcard|privilege|admin|deploy[- ]?role|permission|policy\.json"),
    (2, r"public|bucket|\bs3\b|principal|database|\brds\b|\bdb\b|subnet|storage|exposed"),
]

PLANTED_LITERALS = ["Rp0rts-Stg-2026"]
SECRET_KEY_RE = re.compile(r"(key|secret|password|passwd|token)", re.I)
URL_WITH_PASSWORD = re.compile(r"://[^/\s:@]+:([^@\s]+)@")
READ_ONLY_VERB = re.compile(r"^(get|list|describe|batchget)", re.I)


# --------------------------------------------------------------------------- helpers

def read(root: Path, rel: str) -> str | None:
    path = root / rel
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def listify(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def strip_hcl_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(re.sub(r"\s(#|//).*$", "", line) if not re.match(r"\s*(#|//)", line) else ""
                     for line in text.splitlines())


def terraform(root: Path) -> str:
    folder = root / "infra" / "terraform"
    if not folder.is_dir():
        return ""
    return strip_hcl_comments("\n".join(p.read_text(encoding="utf-8", errors="replace")
                                        for p in sorted(folder.glob("*.tf"))))


def brace_body(text: str, start: int) -> str:
    depth, i = 1, start
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[start:i - 1]


def resources(text: str, rtype: str) -> list[tuple[str, str]]:
    pattern = re.compile(r'resource\s+"' + re.escape(rtype) + r'"\s+"([^"]+)"\s*\{')
    return [(m.group(1), brace_body(text, m.end())) for m in pattern.finditer(text)]


def nested_blocks(text: str, keyword: str) -> list[str]:
    return [brace_body(text, m.end()) for m in re.finditer(r"\b" + keyword + r"\s*\{", text)]


def attr(body: str, name: str) -> str | None:
    m = re.search(r"(?<![\w.])" + name + r"\s*=\s*(\"[^\"]*\"|[^\s]+)", body)
    return m.group(1).strip('"') if m else None


TFVARS = ""  # set in main(): contents of infra/terraform/*.tfvars


def resolve(tf: str, value: str | None) -> str | None:
    """Resolve var.x to its .tfvars assignment, else the variable's default."""
    if not value or not value.startswith("var."):
        return value
    name = value[4:]
    assigned = re.findall(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*(\S+)\s*$", TFVARS)
    if assigned:
        return assigned[-1].strip('"')
    block = re.search(r'variable\s+"' + re.escape(name) + r'"\s*\{', tf)
    if block:
        return attr(brace_body(tf, block.end()), "default")
    return None


def load_pipeline(root: Path):
    text = read(root, "pipeline/ci-cd.yml")
    if text is None:
        return None, None
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return text, None
    return text, doc if isinstance(doc, dict) else None


def jobs_of(doc: dict) -> dict:
    return {k: v for k, v in (doc.get("jobs") or {}).items() if isinstance(v, dict)}


def all_steps(doc: dict):
    for job in jobs_of(doc).values():
        for step in listify(job.get("steps")):
            if isinstance(step, dict):
                yield step


def version(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", text)[:3])


def production_deploy_jobs(jobs: dict) -> list[str]:
    deploys = [k for k in jobs if "deploy" in k.lower()]
    prod = [k for k in deploys if "prod" in k.lower() or str(jobs[k].get("environment", "")).startswith("prod")
            or (isinstance(jobs[k].get("environment"), dict) and "prod" in str(jobs[k]["environment"].get("name", "")))]
    return prod or deploys


# --------------------------------------------------------------------------- checks

def check_identity(root: Path) -> bool:
    text = read(root, "infra/iam/deploy-role-policy.json")
    if text is None:
        return False
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return False
    allows = [s for s in listify(doc.get("Statement")) if isinstance(s, dict) and s.get("Effect") == "Allow"]
    if not allows:
        return False
    can_still_deploy = False
    for stmt in allows:
        if "NotAction" in stmt or "NotResource" in stmt:
            return False
        actions = [str(a) for a in listify(stmt.get("Action"))]
        if not actions or any(a == "*" or a.endswith(":*") for a in actions):
            return False
        verbs = [a.split(":", 1)[-1] for a in actions]
        if "*" in [str(r) for r in listify(stmt.get("Resource"))]:
            # Resource "*" is acceptable only for read-only calls such as ecr:GetAuthorizationToken.
            if not all(READ_ONLY_VERB.match(v) for v in verbs):
                return False
        if any(not READ_ONLY_VERB.match(v) for v in verbs):
            can_still_deploy = True
    return can_still_deploy


def check_data_exposure(root: Path) -> bool:
    tf = terraform(root)
    pabs = resources(tf, "aws_s3_bucket_public_access_block")
    dbs = resources(tf, "aws_db_instance")
    if not resources(tf, "aws_s3_bucket") or not pabs or not dbs:
        return False
    settings = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
    for _, body in pabs:
        if any(attr(body, s) != "true" for s in settings):
            return False
    restrictive = re.compile(r"aws:SourceVpce|aws:SourceVpc\b|aws:PrincipalOrgID|aws:SourceArn|aws:SourceAccount|aws:PrincipalArn", re.I)
    for _, body in resources(tf, "aws_s3_bucket_policy") + [("doc", b) for b in nested_blocks(tf, 'data\\s+"aws_iam_policy_document"\\s+"[^"]+"')]:
        public = re.search(r'Principal\s*[=:]\s*"\*"|"AWS"\s*[=:]\s*"\*"|identifiers\s*=\s*\[\s*"\*"\s*\]', body)
        allows = re.search(r'Effect\s*[=:]\s*"Allow"', body) or "effect" not in body.lower()
        if public and allows and not restrictive.search(body):
            return False
    if re.search(r'acl\s*=\s*"public-read', tf):
        return False
    for _, body in dbs:
        if resolve(tf, attr(body, "publicly_accessible")) == "true":
            return False
    return True


def check_secrets(root: Path) -> bool:
    text, doc = load_pipeline(root)
    if doc is None or not production_deploy_jobs(jobs_of(doc)):
        return False
    if any(lit in text for lit in PLANTED_LITERALS):
        return False

    def bad_value(key: str, value) -> bool:
        value = str(value)
        match = URL_WITH_PASSWORD.search(value)
        if match and "secrets." not in match.group(1):
            return True
        if SECRET_KEY_RE.search(key) and value.strip():
            return "secrets." not in value
        return False

    def walk(node, parent=None) -> bool:
        if isinstance(node, dict):
            for key, value in node.items():
                if parent != "permissions" and isinstance(value, (str, int, float)) and bad_value(str(key), value):
                    return False
                if not walk(value, str(key)):
                    return False
        elif isinstance(node, list):
            return all(walk(item, parent) for item in node)
        elif isinstance(node, str) and parent in ("run",) and URL_WITH_PASSWORD.search(node):
            return "secrets." in URL_WITH_PASSWORD.search(node).group(1)
        return True

    return walk(doc)


def check_supply_chain(root: Path) -> bool:
    req = read(root, "app/requirements.txt")
    docker = read(root, "app/Dockerfile")
    if req is None or docker is None or not re.search(r"^\s*FROM\s", docker, re.M | re.I):
        return False
    if re.search(r"^\s*(--extra-index-url|--trusted-host|-i\s|--index-url\s+http://)", req, re.M):
        return False
    minimum = {"pyyaml": (5, 4), "requests": (2, 32, 0), "flask": (3, 0)}
    found = {}
    for line in req.splitlines():
        line = line.split("#")[0].strip()
        m = re.match(r"([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=)\s*([0-9][0-9.]*)", line)
        if m:
            found[m.group(1).lower()] = version(m.group(4))
    for pkg, floor in minimum.items():
        if pkg not in found or found[pkg] < floor:
            return False
    if re.search(r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b", docker):
        return False
    for line in re.findall(r"(?im)^\s*ADD\s+[^\n]*", docker):
        if re.search(r"https?://", line) and "--checksum=" not in line:
            return False
    return True


def check_release_gate(root: Path) -> bool:
    _, doc = load_pipeline(root)
    if doc is None:
        return False
    jobs = jobs_of(doc)
    targets = production_deploy_jobs(jobs)
    if not targets:
        return False
    gate_re = re.compile(r"secur|scan|gate|policy|sast|trivy|checkov|grype|snyk|audit|conftest|opa", re.I)
    soft_re = re.compile(r"--exit-code[ =]0\b|--soft-fail|\|\|\s*true|;\s*true\s*$|--no-fail|exit 0", re.M)

    def blocking(job: dict) -> bool:
        steps = [s for s in listify(job.get("steps")) if isinstance(s, dict)]
        if not steps or job.get("continue-on-error"):
            return False
        for step in steps:
            if step.get("continue-on-error") or soft_re.search(str(step.get("run", ""))):
                return False
            if str(step.get("with", "")).lower().find("soft_fail': true") >= 0:
                return False
        return True

    for target in targets:
        seen, frontier = set(), [str(n) for n in listify(jobs[target].get("needs"))]
        while frontier:
            job_id = frontier.pop()
            if job_id in seen or job_id not in jobs:
                continue
            seen.add(job_id)
            frontier.extend(str(n) for n in listify(jobs[job_id].get("needs")))
        if not any(gate_re.search(j + " " + str(jobs[j].get("name", ""))) and blocking(jobs[j]) for j in seen):
            return False
    return True


def check_network(root: Path) -> bool:
    tf = terraform(root)
    groups = resources(tf, "aws_security_group")
    if not any(name == "build_agents" for name, _ in groups):
        return False

    def wide_open(body: str) -> bool:
        anywhere = "0.0.0.0/0" in body or "::/0" in body
        all_proto = attr(body, "protocol") in ("-1", "all")
        try:
            span = int(attr(body, "to_port") or 0) - int(attr(body, "from_port") or 0)
        except ValueError:
            span = 0
        return anywhere and (all_proto or span >= 1000)

    for name, body in groups:
        if name == "build_agents" and any(wide_open(e) for e in nested_blocks(body, "egress")):
            return False
    for _, body in resources(tf, "aws_security_group_rule"):
        if attr(body, "type") == "egress" and "build_agents" in body and wide_open(body):
            return False
    for _, body in resources(tf, "aws_vpc_security_group_egress_rule"):
        if "build_agents" not in body:
            continue
        anywhere = attr(body, "cidr_ipv4") == "0.0.0.0/0" or attr(body, "cidr_ipv6") == "::/0"
        try:
            span = int(attr(body, "to_port") or 0) - int(attr(body, "from_port") or 0)
        except ValueError:
            span = 0
        if anywhere and (attr(body, "ip_protocol") in ("-1", "all") or span >= 1000):
            return False
    return True


def check_detection(root: Path) -> bool:
    tf = terraform(root)
    if not resources(tf, "aws_db_instance"):
        return False
    trails = resources(tf, "aws_cloudtrail")
    detectors = resources(tf, "aws_guardduty_detector")
    if any(resolve(tf, attr(b, "enable_logging")) == "false" for _, b in trails):
        return False
    if any(resolve(tf, attr(b, "enable")) == "false" for _, b in detectors):
        return False
    return bool(trails) and bool(detectors)


def check_recovery(root: Path) -> bool:
    _, doc = load_pipeline(root)
    deployment_text = read(root, "k8s/deployment.yaml")
    if doc is None or deployment_text is None:
        return False
    try:
        manifests = [m for m in yaml.safe_load_all(deployment_text) if isinstance(m, dict)]
    except yaml.YAMLError:
        return False
    deployments = [m for m in manifests if m.get("kind") == "Deployment"]
    if not deployments:
        return False
    for dep in deployments:
        limit = (dep.get("spec") or {}).get("revisionHistoryLimit", 10)
        if not isinstance(limit, int) or limit < 1:
            return False
    action = re.compile(r"rollout\s+undo|helm\s+rollback|argo\S*\s+rollouts\s+(undo|abort)|stop-deployment|rollback\.sh", re.I)
    jobs = jobs_of(doc)
    for target in production_deploy_jobs(jobs):
        for step in listify(jobs[target].get("steps")):
            if not isinstance(step, dict):
                continue
            run = "\n".join(line for line in str(step.get("run", "")).splitlines()
                            if not re.match(r"\s*(echo|printf|#)", line))
            if action.search(run) or action.search(str(step.get("uses", ""))):
                return True
    return False


CHECKS = {
    1: check_identity,
    2: check_data_exposure,
    3: check_secrets,
    4: check_supply_chain,
    5: check_release_gate,
    6: check_network,
    7: check_detection,
    8: check_recovery,
}


# --------------------------------------------------------------------------- build sanity

def build_problems(root: Path) -> list[str]:
    problems = []
    src = root / "app" / "src" / "reports"
    if not (src / "main.py").is_file():
        problems.append("app/src/reports/main.py is missing")
    for path in sorted(src.glob("*.py")) if src.is_dir() else []:
        try:
            compile(path.read_text(encoding="utf-8", errors="replace"), str(path.name), "exec")
        except SyntaxError as err:
            problems.append(f"app/src/reports/{path.name} does not compile (line {err.lineno})")
    for rel in ("infra/iam/deploy-role-policy.json", "infra/iam/deploy-role-trust.json"):
        try:
            json.loads(read(root, rel) or "")
        except json.JSONDecodeError:
            problems.append(f"{rel} is missing or not valid JSON")
    _, doc = load_pipeline(root)
    if doc is None:
        problems.append("pipeline/ci-cd.yml is missing or not valid YAML")
    for path in sorted((root / "k8s").glob("*.yaml")) if (root / "k8s").is_dir() else []:
        try:
            list(yaml.safe_load_all(path.read_text(encoding="utf-8", errors="replace")))
        except yaml.YAMLError:
            problems.append(f"k8s/{path.name} is not valid YAML")
    folder = root / "infra" / "terraform"
    for path in sorted(folder.glob("*.tf")) if folder.is_dir() else []:
        body = strip_hcl_comments(path.read_text(encoding="utf-8", errors="replace"))
        body = re.sub(r'"(?:\\.|[^"\\])*"', '""', body)
        if body.count("{") != body.count("}"):
            problems.append(f"infra/terraform/{path.name} has unbalanced braces")
    for rel in ("app/requirements.txt", "app/Dockerfile", "k8s/deployment.yaml",
                "infra/terraform/storage.tf", "infra/terraform/database.tf"):
        if read(root, rel) is None:
            problems.append(f"{rel} is missing")
    return problems


# --------------------------------------------------------------------------- DECISION.md

def score_decision(root: Path) -> tuple[dict[int, bool], int, str]:
    text = read(root, "DECISION.md") or ""
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
    classified: dict[int, bool] = {}
    for line in text.splitlines():
        if not line.strip().startswith("|") or re.match(r"^\s*\|[\s:\-|]+\|\s*$", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 4 or cells[3].lower() in ("type", ""):
            continue
        described = (cells[1] + " " + cells[2]).lower()
        kind = cells[3].lower()
        kind = next((k for k in ("sensor", "constraint", "actuation") if k in kind), "")
        for check_id, pattern in ROW_KEYWORDS:
            if check_id not in classified and re.search(pattern, described):
                classified[check_id] = kind in EXPECTED_TYPES[check_id]
                break

    verdict_points = 0
    decision = re.search(r"^[ \t]*Decision[ \t]*:[ \t]*(.*)$", text, re.M | re.I)
    decision_text = decision.group(1).strip().upper() if decision else ""
    if re.search(r"DO NOT|DON'T|\bNO\b|BLOCK|REJECT", decision_text):
        verdict_points += 4
    rules = re.search(r"^[ \t]*Rules? triggered[ \t]*:[ \t]*(.*)$", text, re.M | re.I)
    cited = set(re.findall(r"\b([1-5])\b", rules.group(1) if rules else ""))
    if verdict_points:
        verdict_points += 3 * len({"2", "3"} & cited)
    return classified, verdict_points, decision_text or "not stated"


# --------------------------------------------------------------------------- main

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--team", required=True)
    parser.add_argument("--sha", default="")
    parser.add_argument("--out")
    parser.add_argument("--summary")
    args = parser.parse_args()

    root = Path(args.repo).resolve()
    global TFVARS
    tf_dir = root / "infra" / "terraform"
    TFVARS = strip_hcl_comments("\n".join(p.read_text(encoding="utf-8", errors="replace")
                                          for p in sorted(tf_dir.glob("*.tfvars")))) if tf_dir.is_dir() else ""
    team =re.sub(r"[^a-z0-9-]", "-", args.team.lower()).strip("-")[:40] or "unnamed"

    fixes = {}
    for check_id, check in CHECKS.items():
        try:
            fixes[check_id] = bool(check(root))
        except Exception:  # a malformed file never crashes the scorer
            fixes[check_id] = False

    problems = build_problems(root)
    classified, verdict_points, decision_text = score_decision(root)

    fix_score = FIX_POINTS * sum(fixes.values())
    class_score = CLASS_POINTS * sum(classified.values())
    total = max(0, fix_score + class_score + verdict_points - (BROKEN_PENALTY if problems else 0))

    result = {
        "team": team,
        "score": total,
        "max": FIX_POINTS * 8 + CLASS_POINTS * 8 + 10,
        "fixed": sum(fixes.values()),
        "checks": {str(k): v for k, v in fixes.items()},
        "classified": sum(classified.values()),
        "verdict_points": verdict_points,
        "build_ok": not problems,
        "sha": args.sha[:7],
        "scored_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    lines = [
        f"## Team `{team}`: {total} / {result['max']}",
        "",
        "| Check | Status |",
        "|---|---|",
    ]
    for check_id, ok in fixes.items():
        lines.append(f"| {check_id} · {AREAS[check_id] if ok else '?'} | {'Fixed' if ok else 'Not yet'} |")
    lines += [
        "",
        f"- Flaws fixed: **{result['fixed']} / 8** ({fix_score} pts)",
        f"- Correct classifications in DECISION.md: **{result['classified']} / 8** ({class_score} pts)",
        f"- Verdict: **{decision_text}** ({verdict_points} / 10 pts)",
    ]
    if problems:
        lines += ["", f"**Build broken (−{BROKEN_PENALTY}):**"] + [f"- {p}" for p in problems]
    summary = "\n".join(lines) + "\n"

    print(summary)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(summary)
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
