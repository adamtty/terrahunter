"""AWS IAM, as the configuration sets it up: what each identity may do, and who may become a role.

- **permissions**: every statement that applies to a user or role, from wherever it's written: the identity's own
  `inline_policy` blocks and `managed_policy_arns`, policy attachments (also `*_exclusive` ones and those of its
  groups), customer-managed policies, `data "aws_iam_policy_document"`, and AWS managed policies (from the knowledge
  base). Each statement keeps its effect, its actions (or NotAction), the resources it names (resolved to resources
  in the graph where it references them, or names them by ARN) and whether it has a Condition;
- **allowed(identity, action, resource)**: True, False, or None when only a conditional statement allows it. An
  explicit Deny wins, as in IAM;
- **trust**: who a role's `assume_role_policy` lets assume it: principals it references, the account root (any
  principal of the account its own policies let call sts:AssumeRole on the role), `*`, and services;
- **access(identity, resource)**: the strongest access the identity's statements give on a resource (admin, write,
  read, list), by the knowledge base's access levels for the actions.

Permission boundaries, SCPs, session policies and resource policies are not evaluated here.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import cached_property

from terrahunter import deps, graph, kb, policies

POLICY_TYPES = (
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
    "aws_iam_role_policy_attachments_exclusive",
    "aws_iam_user_policy_attachments_exclusive",
    "aws_iam_group_policy_attachments_exclusive",
)
IDENTITIES = ("aws_iam_user", "aws_iam_role")
# a reference in a policy string: ${aws_s3_bucket.data.arn}, ${module.x.aws_iam_role.r.arn}
_REF = re.compile(r"\$\{(?:data\.)?([a-z][a-z0-9_]*)\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?\.[A-Za-z0-9_]+\}")
_ROOT = re.compile(r":root$|^\d{12}$")
LEVELS = {"list": 1, "read": 2, "write": 3, "admin": 4}
_KB_LEVEL = {"List": "list", "Read": "read", "Write": "write", "Tagging": "write", "Permissions management": "admin"}
# the attributes that hold a resource's own name, as a literal ARN may name it
_NAME_ATTRS = ("name", "bucket", "function_name", "name_prefix", "repository_name", "cluster_identifier", "identifier")


def _list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def _s(v) -> str:
    u = deps.unquote(v)
    return u if u is not None else (str(v) if v is not None else "")


@dataclass
class Statement:
    effect: str  # Allow | Deny
    actions: list[str]  # lower case patterns; empty with not_actions
    not_actions: list[str]
    resources: list[str]  # as written: "*", ARNs, ${…} references
    not_resources: list[str]
    conditional: bool
    source: str  # the resource the statement is written in
    targets: set[str] = field(default_factory=set)  # graph resources its Resource references or names

    def covers_action(self, action: str) -> bool:
        a = action.lower()
        if self.not_actions:
            return not any(fnmatch.fnmatchcase(a, p) for p in self.not_actions)
        return any(fnmatch.fnmatchcase(a, p) for p in self.actions)

    def covers(self, resource: str | None, names: dict[str, set[str]]) -> bool:
        """Whether the statement's resources include a graph resource (None: any resource, "*" only)."""
        if self.not_resources:
            return resource is None or resource not in self.targets
        if any(r == "*" for r in self.resources):
            return True
        if resource is None:
            return False
        if resource in self.targets:
            return True
        own = names.get(resource, set())
        return any(_arn_names(r, own) for r in self.resources if "${" not in r)


def _arn_names(pattern: str, own: set[str]) -> bool:
    """Whether a literal ARN pattern names a resource by one of its own names (the last part of the ARN)."""
    tail = re.split(r"[:/]", pattern.split("/*")[0])[-1] if pattern.startswith("arn:") else pattern
    return bool(tail) and any(fnmatch.fnmatchcase(n, tail) for n in own)


class Model:
    def __init__(self, g: graph.Graph):
        self.g = g
        R = g.resources
        self.out_e: dict[str, list[graph.Edge]] = {}
        self.in_e: dict[str, list[graph.Edge]] = {}
        for e in g.edges:
            self.out_e.setdefault(e.source, []).append(e)
            self.in_e.setdefault(e.target, []).append(e)
        self._statements: dict[str, list[Statement]] = {}
        self.identities = [a for a, r in R.items() if r.mode == "managed" and r.type in IDENTITIES]

    # --- documents ---------------------------------------------------------------------------------------------
    def _module(self, addr: str) -> str:
        r = self.g.resources.get(addr)
        return f"{r.module}." if r and r.module else ""

    def _doc(self, addr: str, attr: str, value) -> dict | None:
        """A policy attribute's document: literal JSON or jsonencode, or the data document it names."""
        doc = policies.document(value)
        if doc is not None:
            return doc
        R = self.g.resources
        for e in self.out_e.get(addr, []):
            if e.attr == attr and e.target in R and R[e.target].type == "aws_iam_policy_document":
                return policies.render_document(R[e.target].body)
        return None

    def _statements_of(self, doc: dict, source: str) -> list[Statement]:
        out = []
        R = self.g.resources
        for st in _list(doc.get("Statement")):
            if not isinstance(st, dict):
                continue
            res = [str(x) for x in _list(st.get("Resource"))]
            targets = set()
            for r in res + [str(x) for x in _list(st.get("NotResource"))]:
                for t, n in _REF.findall(r):
                    addr = f"{self._module(source)}{t}.{n}"
                    if addr in R:
                        targets.add(addr)
            out.append(
                Statement(
                    effect=str(st.get("Effect", "Allow")),
                    actions=[str(a).lower() for a in _list(st.get("Action"))],
                    not_actions=[str(a).lower() for a in _list(st.get("NotAction"))],
                    resources=res,
                    not_resources=[str(x) for x in _list(st.get("NotResource"))],
                    conditional=bool(st.get("Condition")),
                    source=source,
                    targets=targets,
                )
            )
        return out

    def groups(self, identity: str) -> list[str]:
        R = self.g.resources
        out = [
            e.target for e in self.out_e.get(identity, []) if R.get(e.target) and R[e.target].type == "aws_iam_group"
        ]
        for e in self.in_e.get(identity, []):
            if R[e.source].type in ("aws_iam_user_group_membership", "aws_iam_group_membership"):
                out += [
                    x.target
                    for x in self.out_e.get(e.source, [])
                    if R.get(x.target) and R[x.target].type == "aws_iam_group"
                ]
        return list(dict.fromkeys(out))

    def _managed(self, arn: str, source: str) -> list[Statement]:
        name = arn.rsplit("/", 1)[-1] if arn.startswith("arn:aws:iam::aws:policy/") else ""
        doc = kb.managed_policy(name) if name else None
        return self._statements_of(doc, source) if doc else []

    def statements(self, identity: str) -> list[Statement]:
        """Every statement that applies to a user or role."""
        if identity in self._statements:
            return self._statements[identity]
        R = self.g.resources
        out: list[Statement] = []
        for holder in [identity, *self.groups(identity)]:
            if holder not in R:
                continue
            b = R[holder].body
            for blk in _list(b.get("inline_policy")):  # the identity's own inline policies
                if isinstance(blk, dict):
                    doc = self._doc(holder, "inline_policy.policy", blk.get("policy"))
                    out += self._statements_of(doc, holder) if doc else []
            for arn in _list(b.get("managed_policy_arns")):
                out += self._policy_arn(holder, "managed_policy_arns", arn)
            for e in self.in_e.get(holder, []):
                p = e.source
                if R[p].type not in POLICY_TYPES:
                    continue
                pb = R[p].body
                if pb.get("policy") is not None:  # an inline role / user / group policy
                    doc = self._doc(p, "policy", pb.get("policy"))
                    out += self._statements_of(doc, p) if doc else []
                for attr in ("policy_arn", "policy_arns"):
                    for arn in _list(pb.get(attr)):
                        out += self._policy_arn(p, attr, arn)
        self._statements[identity] = out
        return out

    def _policy_arn(self, holder: str, attr: str, arn) -> list[Statement]:
        """A policy named by ARN: an AWS managed policy, or a customer-managed one the configuration creates."""
        R = self.g.resources
        lit = deps.unquote(arn)
        if lit:
            return self._managed(lit, holder)
        out = []
        for e in self.out_e.get(holder, []):
            if e.attr == attr and e.target in R and R[e.target].type == "aws_iam_policy":
                pol = R[e.target]
                doc = self._doc(e.target, "policy", pol.body.get("policy"))
                out += self._statements_of(doc, e.target) if doc else []
        return out

    # --- decisions ---------------------------------------------------------------------------------------------
    @cached_property
    def names(self) -> dict[str, set[str]]:
        """Each resource's own names (for literal ARNs that name it): its name-like attributes' literal values."""
        out: dict[str, set[str]] = {}
        for a, r in self.g.resources.items():
            vals = {deps.unquote(r.body.get(k)) for k in _NAME_ATTRS}
            out[a] = {v for v in vals if v}
        return out

    def allowed(self, identity: str, action: str, resource: str | None = None) -> bool | None:
        """Whether the identity's statements allow an action on a resource (None: on "*" only)."""
        sts = [s for s in self.statements(identity) if s.covers_action(action) and s.covers(resource, self.names)]
        if any(s.effect == "Deny" and not s.conditional for s in sts):
            return False
        allows = [s for s in sts if s.effect == "Allow"]
        if any(not s.conditional for s in allows):
            return None if any(s.effect == "Deny" for s in sts) else True
        return None if allows else False

    def why(self, identity: str, action: str, resource: str | None = None) -> str:
        """The resource whose statement allows it (for the hop text and the fix)."""
        for s in self.statements(identity):
            if s.effect == "Allow" and s.covers_action(action) and s.covers(resource, self.names):
                return s.source
        return ""

    def access(self, identity: str, resource: str, service: str) -> str:
        """The strongest access the identity has on a resource of an IAM service ("" for none): `*` or `svc:*` is
        admin; otherwise the knowledge base's access level of each action it's allowed."""
        best = ""
        for s in self.statements(identity):
            if s.effect != "Allow" or s.conditional or not s.covers(resource, self.names):
                continue
            if s.not_actions or any(p in ("*", f"{service}:*") for p in s.actions):
                level = "admin"
            else:
                level = ""
                for p in s.actions:
                    if p.split(":")[0] != service and not fnmatch.fnmatchcase(service, p.split(":")[0]):
                        continue
                    for _, lvl in kb.aws_actions(p):
                        mine = _KB_LEVEL.get(lvl, "")
                        if LEVELS.get(mine, 0) > LEVELS.get(level, 0):
                            level = mine
            if LEVELS.get(level, 0) > LEVELS.get(best, 0):
                best = level
        return best

    # --- trust -------------------------------------------------------------------------------------------------
    def trust(self, role: str) -> list[Statement]:
        R = self.g.resources
        r = R.get(role)
        if not r or r.type != "aws_iam_role":
            return []
        doc = self._doc(role, "assume_role_policy", r.body.get("assume_role_policy"))
        out = []
        for st in _list((doc or {}).get("Statement")):
            if isinstance(st, dict) and str(st.get("Effect", "Allow")) == "Allow":
                pr = st.get("Principal")
                principals = (
                    {"AWS": ["*"]}
                    if pr == "*"
                    else {k: _list(v) for k, v in pr.items()}
                    if isinstance(pr, dict)
                    else {}
                )
                s = Statement("Allow", [], [], [], [], bool(st.get("Condition")), role)
                s.resources = [f"{k}:{x}" for k, vs in principals.items() for x in vs]  # principals, kind:value
                out.append(s)
        return out

    def services(self, role: str) -> set[str]:
        """The services a role trusts (lambda.amazonaws.com)."""
        return {p.split(":", 1)[1].lower() for s in self.trust(role) for p in s.resources if p.startswith("Service:")}

    def can_assume(self, principal: str, role: str) -> bool | None:
        """Whether a user or role can become the role: the trust policy names it, `*`, or the account root and its
        own policies allow sts:AssumeRole on the role. None when only a conditional statement admits it."""
        R = self.g.resources
        mod = self._module(role)
        best: bool | None = False
        for s in self.trust(role):
            for p in s.resources:
                kind, _, value = p.partition(":")
                if kind != "AWS":
                    continue
                named = {f"{mod}{t}.{n}" for t, n in _REF.findall(value) if f"{mod}{t}.{n}" in R}
                if principal in named or value == "*":
                    ok: bool | None = True if not s.conditional else None
                    if value == "*":  # anyone's trust still needs the caller's own permission
                        ok = self.allowed(principal, "sts:AssumeRole", role) if ok else ok
                elif _ROOT.search(value):  # the account root, written as an ARN or an account id
                    ok = self.allowed(principal, "sts:AssumeRole", role)
                    ok = None if ok and s.conditional else ok
                else:
                    continue
                if ok is True:
                    return True
                if ok is None:
                    best = None
        return best
