"""Resource policies: which ones let anyone in.

A resource policy is written three ways in Terraform: a JSON string (often a heredoc), `jsonencode({...})`, or a
reference to a `data "aws_iam_policy_document"`. All three are read into the same statements here, and a statement
is **public** when it allows a wildcard principal (`"*"`, `{"AWS": "*"}`, a `principals` block of type `*` or
identifiers `*`) without a condition that pins the caller down (a source IP range, VPC, endpoint, account,
organisation or ARN: the keys S3 itself uses to decide a policy isn't public).

What each policy exposes (AWS):

- an S3 bucket policy: the bucket, unless Block Public Access restricts public policies on the bucket or account;
- an SNS topic or SQS queue policy: the topic or queue (any AWS account can publish, subscribe or send);
- a Lambda permission for principal `*` with no source: the function (anyone can invoke it);
- an API Gateway method with no authorizer on a public REST API, or an HTTP API route with none: the API, which
  invokes what its integrations point at.
"""

from __future__ import annotations

import json
import re

import hcl2

from terrahunter import deps

# condition keys that pin the caller to a network, account, organisation or ARN (S3's "not public" list)
RESTRICTING = {
    "aws:sourceip",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceaccount",
    "aws:sourcearn",
    "aws:sourceowner",
    "aws:sourceorgid",
    "aws:sourceorgpaths",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalaccount",
    "aws:principalarn",
    "aws:userid",
    "aws:username",
    "aws:principalservicename",
    "aws:principalservicenameslist",
    "s3:dataaccesspointaccount",
    "s3:dataaccesspointarn",
    "lambda:functionurlauthtype",
}
_HEREDOC = re.compile(r"^<<-?(\w+)\n(.*)\n\s*\1\s*$", re.DOTALL)
_JSONENCODE = re.compile(r"^\$\{jsonencode\((.*)\)\}$", re.DOTALL)


def _unquote_all(v):
    if isinstance(v, str):
        u = deps.unquote(v)
        return u if u is not None else v
    if isinstance(v, list):
        return [_unquote_all(x) for x in v]
    if isinstance(v, dict):
        return {(deps.unquote(k) or k): _unquote_all(x) for k, x in v.items() if not str(k).startswith("__")}
    return v


def document(value, any_json: bool = False):
    """A policy attribute's value → the policy as a dict, when it's a literal: JSON text, a heredoc of JSON, or
    jsonencode of an object (read with the HCL parser). None for anything else (a reference, an expression).
    `any_json` accepts any JSON value (a list: ECS container definitions), not only an object."""
    if isinstance(value, (dict, list)) and any_json or isinstance(value, dict):
        return _unquote_all(value)
    if not isinstance(value, str):
        return None
    s = value.strip()
    if len(s) >= 2 and s[0] == s[-1] == '"':
        s = s[1:-1]  # interpolations inside JSON string values (an ARN) don't stop it being read
    if not s:
        return None
    m = _HEREDOC.match(s)
    if m:
        s = m.group(2)
    m = _JSONENCODE.match(s)
    if m:
        try:
            parsed = hcl2.loads(f"x = {m.group(1)}\n").get("x")
        except Exception:  # noqa: BLE001 - an expression the parser can't read isn't a literal policy
            return None
        ok = isinstance(parsed, (dict, list)) if any_json else isinstance(parsed, dict)
        return _unquote_all(parsed) if ok else None
    try:
        doc = json.loads(s)
    except (ValueError, RecursionError):
        return None
    return doc if isinstance(doc, (dict, list) if any_json else dict) else None


def _list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def statements(doc: dict) -> list[dict]:
    """Statements in one shape: {effect, principals (a set of 'AWS:x' / 'Service:x' / '*'), actions, conditions
    (a set of lower-case keys), condition_values (key → values)}."""
    out = []
    for st in _list(doc.get("Statement")):
        if not isinstance(st, dict):
            continue
        p = st.get("Principal")
        principals: set[str] = set()
        if p == "*":
            principals.add("*")
        elif isinstance(p, dict):
            for kind, ids in p.items():
                principals |= {f"{kind}:{i}" for i in _list(ids)}
        conds, values = set(), {}
        for _, kv in (st.get("Condition") or {}).items() if isinstance(st.get("Condition"), dict) else []:
            for k, v in kv.items() if isinstance(kv, dict) else []:
                conds.add(str(k).lower())
                values[str(k).lower()] = [str(x) for x in _list(v)]
        out.append(
            {
                "effect": str(st.get("Effect", "Allow")),
                "principals": principals,
                "actions": {str(a) for a in _list(st.get("Action"))},
                "conditions": conds,
                "condition_values": values,
            }
        )
    return out


def document_statements(body: dict) -> list[dict]:
    """Statements of a `data "aws_iam_policy_document"` body."""
    out = []
    for st in _list(body.get("statement")):
        if not isinstance(st, dict):
            continue
        principals: set[str] = set()
        for pr in _list(st.get("principals")):
            if isinstance(pr, dict):
                kind = deps.unquote(pr.get("type")) or ""
                for i in _list(pr.get("identifiers")):
                    i = deps.unquote(i) or str(i)
                    principals.add("*" if kind == "*" or (kind == "AWS" and i == "*") else f"{kind}:{i}")
        conds, values = set(), {}
        for c in _list(st.get("condition")):
            if isinstance(c, dict):
                k = (deps.unquote(c.get("variable")) or "").lower()
                conds.add(k)
                values[k] = [deps.unquote(v) or str(v) for v in _list(c.get("values"))]
        out.append(
            {
                "effect": deps.unquote(st.get("effect")) or "Allow",
                "principals": principals,
                "actions": {deps.unquote(a) or str(a) for a in _list(st.get("actions"))},
                "conditions": conds,
                "condition_values": values,
            }
        )
    return out


def is_public(st: dict) -> bool:
    if st["effect"] != "Allow" or not ({"*", "AWS:*"} & st["principals"]):
        return False
    for k in st["conditions"] & RESTRICTING:
        if k == "aws:sourceip" and all(v in ("0.0.0.0/0", "::/0") for v in st["condition_values"].get(k, [])):
            continue  # a "restriction" to every address isn't one
        return False
    return True


def public_actions(R: dict, addr: str, attr: str, targets) -> list[str]:
    """The actions a resource's policy attribute grants to anyone ([] when none, or when it can't be read)."""
    r = R[addr]
    sts: list[dict] = []
    doc = document(r.body.get(attr))
    if doc is not None:
        sts = statements(doc)
    else:
        for d in targets(addr, "aws_iam_policy_document", attr=rf"^{attr}$"):
            sts += document_statements(R[d].body)
    return sorted({a for st in sts if is_public(st) for a in st["actions"]})


def _bool(v) -> bool:
    return str(deps.unquote(v) if isinstance(v, str) else v).lower() == "true"


def aws_exposure(R: dict, targets, sources, of) -> dict[str, list[tuple[str, str]]]:
    """AWS resources a policy opens to anyone: resource → [(reason, the policy resource)]."""
    exposed: dict[str, list[tuple[str, str]]] = {}

    def add(t: str, why: str, origin: str) -> None:
        exposed.setdefault(t, []).append((why, origin))

    def short(actions: list[str]) -> str:
        return ", ".join(actions[:3]) + (" …" if len(actions) > 3 else "")

    account_restricts = any(
        _bool(R[a].body.get("restrict_public_buckets")) for a in of("aws_s3_account_public_access_block")
    )
    for b in of("aws_s3_bucket"):
        bpa = [x for x in sources(b, "aws_s3_bucket_public_access_block")]
        if account_restricts or any(_bool(R[x].body.get("restrict_public_buckets")) for x in bpa):
            continue  # S3 ignores public policies on this bucket
        for pol in [*sources(b, "aws_s3_bucket_policy"), b]:
            acts = public_actions(R, pol, "policy", targets)
            if acts:
                add(b, f"bucket policy lets anyone {short(acts)}", pol)
    for kind, pol_type, attr in (
        ("aws_sns_topic", "aws_sns_topic_policy", "policy"),
        ("aws_sqs_queue", "aws_sqs_queue_policy", "policy"),
        ("aws_secretsmanager_secret", "aws_secretsmanager_secret_policy", "policy"),
        ("aws_ecr_repository", "aws_ecr_repository_policy", "policy"),
    ):
        for t in of(kind):
            for pol in [*sources(t, pol_type), t]:
                acts = public_actions(R, pol, attr, targets)
                if acts:
                    add(t, f"its policy lets any AWS account {short(acts)}", pol)
    for perm in of("aws_lambda_permission"):
        b = R[perm].body
        if deps.unquote(b.get("principal")) == "*" and not b.get("source_arn") and not b.get("source_account"):
            for fn in targets(perm, "aws_lambda_function"):
                add(fn, "a permission lets anyone invoke it", perm)
    # API Gateway: a method with no authorizer on a REST API that isn't private; an HTTP API route with none
    for m in of("aws_api_gateway_method"):
        if (deps.unquote(R[m].body.get("authorization")) or "NONE") == "NONE":
            for api in targets(m, "aws_api_gateway_rest_api"):
                ec = _list(R[api].body.get("endpoint_configuration"))
                if "PRIVATE" not in str(ec[0].get("types") if ec and isinstance(ec[0], dict) else ""):
                    add(api, f"{deps.unquote(R[m].body.get('http_method')) or 'a'} method with no authorizer", m)
    for rt in of("aws_apigatewayv2_route"):
        if (deps.unquote(R[rt].body.get("authorization_type")) or "NONE") == "NONE":
            for api in targets(rt, "aws_apigatewayv2_api"):
                add(
                    api,
                    f"route {deps.unquote(R[rt].body.get('route_key')) or ''} with no authorizer".replace("  ", " "),
                    rt,
                )
    return exposed
