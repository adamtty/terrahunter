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

from terrahunter import clouds, deps, graph, kb, policies

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
# the account itself as a principal: its root ARN, its id, or the id read from aws_caller_identity
_ROOT = re.compile(r":root$|^\d{12}$|^\$\{data\.aws_caller_identity\.[\w-]+\.account_id\}$")
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
    condition: dict = field(default_factory=dict, repr=False)  # as written

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
        rtype = resource.rsplit(".", 2)[-2] if resource.count(".") >= 1 else ""
        return any(_arn_names(_literal_tail(r), own) or _arn_type(_literal_tail(r)) == rtype for r in self.resources)


def _literal_tail(r: str) -> str:
    """An ARN written with an interpolation in it (arn:aws:iam::${account}:role/app_*): its literal part after the
    last one, which still names the resource ("" when nothing literal is left)."""
    r = r.strip('"')
    if "${" not in r:
        return r
    tail = r.rsplit("}", 1)[-1]
    return tail if "/" in tail or tail.startswith(":") else ""


# the resource type an ARN names before its wildcard (…:user/*, …:function:*) → the Terraform type
_ARN_TYPES = {
    "user": "aws_iam_user",
    "role": "aws_iam_role",
    "group": "aws_iam_group",
    "policy": "aws_iam_policy",
    "instance-profile": "aws_iam_instance_profile",
    "function": "aws_lambda_function",
    "table": "aws_dynamodb_table",
    "secret": "aws_secretsmanager_secret",
    "parameter": "aws_ssm_parameter",
    "instance": "aws_instance",
}


def _arn_type(pattern: str) -> str:
    """The Terraform type of every resource an ARN pattern names by its type alone (…:user/*), or ""."""
    m = re.search(r"(?:^|:)([a-z-]+)[/:]\*$", pattern)
    return _ARN_TYPES.get(m.group(1), "") if m else ""


def _arn_names(pattern: str, own: set[str]) -> bool:
    """Whether a literal ARN pattern names a resource by one of its own names (the last part of the ARN)."""
    if not pattern:
        return False
    named = pattern.startswith(("arn:", ":", "/"))
    tail = re.split(r"[:/]", pattern.split("/*")[0])[-1] if named else pattern
    return bool(tail) and tail != "*" and any(fnmatch.fnmatchcase(n, tail) for n in own)


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
        self._allowed: dict[tuple, bool | None] = {}
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
                    condition=st.get("Condition") if isinstance(st.get("Condition"), dict) else {},
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
        key = (identity, action.lower(), resource)
        if key not in self._allowed:
            self._allowed[key] = self._decide(identity, action, resource)
        return self._allowed[key]

    def _decide(self, identity: str, action: str, resource: str | None) -> bool | None:
        sts = [s for s in self.statements(identity) if s.covers_action(action) and s.covers(resource, self.names)]
        if any(s.effect == "Deny" and not s.conditional for s in sts):
            return False
        allows = [s for s in sts if s.effect == "Allow"]
        if any(not s.conditional or self._tags_hold(s.condition, resource) for s in allows):
            return None if any(s.effect == "Deny" for s in sts) else True
        return None if allows else False

    def _tags_hold(self, condition: dict, resource: str | None) -> bool:
        """Whether a condition is only on the resource's tags (aws:ResourceTag/key equals a value), and the
        resource's own tags meet it."""
        r = self.g.resources.get(resource or "")
        if r is None or not condition:
            return False
        tags = r.body.get("tags") if isinstance(r.body.get("tags"), dict) else {}
        tags = {deps.unquote(k) or k: deps.unquote(v) for k, v in tags.items()}
        for op, tests in condition.items():
            if op not in ("StringEquals", "StringLike") or not isinstance(tests, dict):
                return False
            for key, want in tests.items():
                m = re.fullmatch(r"(?:aws|iam|ec2|ecs|ssm):ResourceTag/(.+)", str(key).strip('"'))
                if not m:
                    return False
                have = tags.get(m.group(1))
                if have is None or not any(fnmatch.fnmatchcase(have, str(w)) for w in _list(want)):
                    return False
        return True

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
            # the actions of the service it allows, each at its access level; an action a Deny takes away doesn't
            # count. Every action of the service (`*`, `svc:*`, NotAction) is admin.
            patterns = (
                [f"{service}:*"]
                if s.not_actions
                else [p for p in s.actions if p == "*" or p.split(":")[0] in (service, "*")]
            )
            whole = s.not_actions or any(p in ("*", f"{service}:*") for p in s.actions)
            level = ""
            for p in patterns:
                for a, lvl in kb.aws_actions(f"{service}:*" if p == "*" else p):
                    if not s.covers_action(a) or self.allowed(identity, a, resource) is not True:
                        continue
                    mine = (
                        "admin"
                        if whole and not self._denied_any(identity, service, resource)
                        else _KB_LEVEL.get(lvl, "")
                    )
                    if LEVELS.get(mine, 0) > LEVELS.get(level, 0):
                        level = mine
            if LEVELS.get(level, 0) > LEVELS.get(best, 0):
                best = level
        return best

    def _denied_any(self, identity: str, service: str, resource: str | None) -> bool:
        """Whether an unconditional Deny takes any of a service's actions away on the resource."""
        return any(
            st.effect == "Deny"
            and not st.conditional
            and st.covers(resource, self.names)
            and (st.not_actions or any(p == "*" or p.split(":")[0] in (service, "*") for p in st.actions))
            for st in self.statements(identity)
        )

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


# --- Azure and Google Cloud ----------------------------------------------------------------------------------------
# where each provider's data plane lives, for an access level on a store (azurerm type prefix → provider)
AZURE_PROVIDERS = {
    "azurerm_storage": "Microsoft.Storage",
    "azurerm_key_vault": "Microsoft.KeyVault",
    "azurerm_cosmosdb": "Microsoft.DocumentDB",
    "azurerm_mssql": "Microsoft.Sql",
    "azurerm_sql": "Microsoft.Sql",
    "azurerm_mysql": "Microsoft.DBforMySQL",
    "azurerm_postgresql": "Microsoft.DBforPostgreSQL",
    "azurerm_managed_disk": "Microsoft.Compute",
    "azurerm_linux_function_app": "Microsoft.Web",
    "azurerm_windows_function_app": "Microsoft.Web",
    "azurerm_function_app": "Microsoft.Web",
    "azurerm_linux_web_app": "Microsoft.Web",
    "azurerm_windows_web_app": "Microsoft.Web",
    "azurerm_app_service": "Microsoft.Web",
    "azurerm_automation": "Microsoft.Automation",
    "azurerm_virtual_machine": "Microsoft.Compute",
    "azurerm_linux_virtual_machine": "Microsoft.Compute",
    "azurerm_windows_virtual_machine": "Microsoft.Compute",
}
_MEMBER_ATTRS = ("member", "members", "role", "condition", "etag", "project")


@dataclass
class Assignment:
    source: str  # the role assignment / IAM binding resource
    role: str
    actions: list[str]  # lower case patterns (Azure operations / GCP permissions)
    not_actions: list[str]
    scope: set[str] | None  # the resources it covers; None: the whole subscription / project
    implied: bool = False  # not in the configuration: a grant the cloud adds by default (the default compute account)

    def __post_init__(
        self,
    ):  # a role has thousands of literal permissions: a set lookup for those, fnmatch for the rest
        self._literal = frozenset(p for p in self.actions if not set(p) & set("*?["))
        self._wild = [p for p in self.actions if set(p) & set("*?[")]

    def grants(self, act: str) -> bool:
        return act in self._literal or _matches(act, self._wild)


class _CloudModel:
    """What Azure and Google Cloud models share with the AWS one: allowed, access, can_assume, is_admin."""

    def __init__(self, g: graph.Graph):
        self.g = g
        self.out_e: dict[str, list[graph.Edge]] = {}
        self.in_e: dict[str, list[graph.Edge]] = {}
        for e in g.edges:
            self.out_e.setdefault(e.source, []).append(e)
            self.in_e.setdefault(e.target, []).append(e)
        self._assignments: dict[str, list[Assignment]] = {}

    def assignments(self, identity: str) -> list[Assignment]:
        raise NotImplementedError

    def _covers(self, a: Assignment, action: str, resource: str | None) -> bool:
        act = action.lower()
        return (
            a.grants(act)
            and not _matches(act, a.not_actions)
            and (a.scope is None or resource is None or resource in a.scope)
        )

    def allowed(self, identity: str, action: str, resource: str | None = None) -> bool | None:
        return any(self._covers(a, action, resource) for a in self.assignments(identity))

    def why(self, identity: str, action: str, resource: str | None = None) -> str:
        return next((a.source for a in self.assignments(identity) if self._covers(a, action, resource)), "")

    def is_admin(self, identity: str) -> bool:
        return any(a.scope is None and a.actions == ["*"] and not a.not_actions for a in self.assignments(identity))

    def can_assume(self, principal: str, role: str) -> bool | None:
        return False

    def services(self, role: str) -> set[str]:
        return set()

    def statements(self, identity: str) -> list:
        return []


class AzureModel(_CloudModel):
    """Azure RBAC: role assignments whose principal_id is an identity's (a user-assigned identity, or the
    system-assigned identity of a workload), with the role's actions and data actions, at their scope."""

    def assignments(self, identity: str) -> list[Assignment]:
        if identity in self._assignments:
            return self._assignments[identity]
        R = self.g.resources
        out = []
        for e in self.in_e.get(identity, []):
            a = e.source
            if R[a].type != "azurerm_role_assignment" or not e.attr.startswith("principal_id"):
                continue
            b = R[a].body
            role = deps.unquote(b.get("role_definition_name")) or ""
            perms = kb.azure_role(role) or []
            for d in self.out_e.get(a, []):  # a custom role definition
                if R.get(d.target) and R[d.target].type == "azurerm_role_definition":
                    role = role or R[d.target].name
                    perms = [
                        {
                            k: [deps.unquote(x) or str(x) for x in _list(p.get(k))]
                            for k in ("actions", "not_actions", "data_actions", "not_data_actions")
                        }
                        for p in _list(R[d.target].body.get("permissions"))
                        if isinstance(p, dict)
                    ]
            acts = [x.lower() for p in perms for x in [*(p.get("actions") or []), *(p.get("data_actions") or [])]]
            nots = [
                x.lower() for p in perms for x in [*(p.get("not_actions") or []), *(p.get("not_data_actions") or [])]
            ]
            out.append(Assignment(a, role or "a role", acts, nots, self._scope(a)))
        self._assignments[identity] = out
        return out

    def _scope(self, a: str) -> set[str] | None:
        R = self.g.resources
        for e in self.out_e.get(a, []):
            t = e.target
            if not e.attr.startswith("scope") or t not in R or R[t].mode != "managed":
                continue  # a data source (the subscription) or no reference: the whole subscription
            if R[t].type == "azurerm_resource_group":  # what lives in the group
                return {x.source for x in self.in_e.get(t, []) if x.attr.startswith("resource_group_name")}
            return {t} | {x.source for x in self.in_e.get(t, [])}  # the resource and what's inside it
        return None

    def access(self, identity: str, resource: str, service: str = "") -> str:
        R = self.g.resources
        prov = next((p for k, p in AZURE_PROVIDERS.items() if R[resource].type.startswith(k)), "")
        best = ""
        for a in self.assignments(identity):
            if a.scope is not None and resource not in a.scope:
                continue
            if any(p in ("*", f"{prov.lower()}/*") for p in a.actions) or any(
                p.endswith("listkeys/action") and p.startswith(prov.lower()) for p in a.actions
            ):
                level = "admin"  # every action, or the account keys, which give every data action
            elif any(p.startswith(prov.lower()) and _azure_writes(p) for p in a.actions):
                level = "write"
            elif any(p.startswith(prov.lower()) or p == "*/read" for p in a.actions):
                level = "read"
            else:
                level = ""
            if LEVELS.get(level, 0) > LEVELS.get(best, 0):
                best = level
        return best


class GcpModel(_CloudModel):
    """Google Cloud IAM: project and resource IAM members and bindings that name a service account, with the role's
    permissions; holding roles/iam.serviceAccountTokenCreator or serviceAccountUser on another service account lets
    it act as that one. A workload running as the default compute service account also holds the Editor role Google
    grants that account (implied, so likely), within its access scopes."""

    def assignments(self, identity: str) -> list[Assignment]:
        if identity in self._assignments:
            return self._assignments[identity]
        R = self.g.resources
        out = []
        for e in self.in_e.get(identity, []):
            b = e.source
            t = R[b].type
            if not re.search(r"_iam_(member|binding)$", t) or not e.attr.startswith("member"):
                continue
            role = deps.unquote(R[b].body.get("role")) or ""
            perms = kb.gcp_role(role)
            if perms is None:  # a custom role the configuration creates
                perms = [
                    deps.unquote(p) or str(p)
                    for x in self.out_e.get(b, [])
                    if R.get(x.target) and R[x.target].type.endswith("_iam_custom_role")
                    for p in _list(R[x.target].body.get("permissions"))
                ]
            acts = (
                ["*"] if role == "roles/owner" or role == "roles/editor" and not perms else [p.lower() for p in perms]
            )
            scope = None
            if not t.startswith(("google_project_iam", "google_organization_iam", "google_folder_iam")):
                scope = {x.target for x in self.out_e.get(b, []) if not x.attr.startswith(_MEMBER_ATTRS)}
            out.append(Assignment(b, role, acts, [], scope))
        if identity in R and clouds.system_identity(R[identity].type, R[identity].body) and not self._deprivileged():
            out.append(self._default_editor(R[identity]))
        self._assignments[identity] = out
        return out

    def _deprivileged(self) -> bool:
        """The configuration takes the default compute account's automatic Editor grant away."""
        return any(
            r.type == "google_project_default_service_accounts"
            and (deps.unquote(r.body.get("action")) or "").upper() in ("DEPRIVILEGE", "DELETE", "DISABLE")
            for r in self.g.resources.values()
        )

    def _default_editor(self, r: graph.Resource) -> Assignment:
        """The default compute service account's Editor role, which Google grants it when the project is created
        (unless an organization policy stops it), cut down to what the workload's access scopes let its token call."""
        perms = [p.lower() for p in kb.gcp_role("roles/editor") or ["*"]]
        if r.type in ("google_compute_instance", "google_compute_instance_template", "google_container_node_pool"):
            sa = clouds._block(r.body, "node_config" if r.type == "google_container_node_pool" else "service_account")
            scopes = [clouds._s(x).rsplit("/", 1)[-1] for x in _list(sa.get("scopes") or sa.get("oauth_scopes"))]
            if "cloud-platform" not in scopes:
                allowed = [p for x in scopes for p in _SCOPES.get(x, [])]
                perms = [p for p in perms if any(fnmatch.fnmatchcase(p, a) for a in allowed)]
        return Assignment(IMPLIED, "roles/editor", perms, [], None, True)

    def access(self, identity: str, resource: str, service: str = "") -> str:
        return self.access_via(identity, resource)[0]

    def access_via(self, identity: str, resource: str) -> tuple[str, str]:
        """The access level on a resource, and the binding (or implied grant) that gives it; explicit bindings win
        a tie."""
        R = self.g.resources
        svc = R[resource].type.split("_")[1] if "_" in R[resource].type else ""
        svc = _GCP_PERMISSION_SERVICE.get(svc, svc)
        best, source = "", ""
        for a in self.assignments(identity):
            if a.scope is not None and resource not in a.scope:
                continue
            mine = [p for p in a.actions if p == "*" or p.startswith(f"{svc}.")]
            if not mine:
                continue
            if "*" in mine or any(p.endswith((".setiampolicy", ".delete")) for p in mine):
                level = "admin"
            elif any(p.endswith((".create", ".update")) for p in mine):
                level = "write"
            else:
                level = "read"
            if LEVELS.get(level, 0) > LEVELS.get(best, 0):
                best, source = level, a.source
        return best, source

    def can_assume(self, principal: str, role: str) -> bool | None:
        """Acting as another service account: token creator or service account user on it, or project-wide."""
        if self.g.resources.get(role) is None or self.g.resources[role].type != "google_service_account":
            return False
        return any(
            self._covers(a, perm, role)
            for a in self.assignments(principal)
            for perm in ("iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.actAs")
        )


class Models:
    """One IAM model per cloud, called by the identity's cloud: the AWS model's interface for all three."""

    def __init__(self, g: graph.Graph):
        self.g = g
        self.aws = Model(g)
        self.azure = AzureModel(g)
        self.gcp = GcpModel(g)
        R = g.resources
        self.identities = self.aws.identities + [
            a
            for a, r in R.items()
            if r.mode == "managed"
            and (r.type in ("azurerm_user_assigned_identity", "google_service_account") or _system_identity(r))
        ]

    def of(self, identity: str):
        t = self.g.resources[identity].type if identity in self.g.resources else ""
        return self.azure if t.startswith("azurerm_") else self.gcp if t.startswith("google_") else self.aws

    def __getattr__(self, name):  # allowed, access, why, can_assume, services, statements: by the identity's cloud
        def call(identity, *args, **kw):
            return getattr(self.of(identity), name)(identity, *args, **kw)

        return call

    def is_admin(self, identity: str) -> bool:
        m = self.of(identity)
        if m is self.aws:
            return m.allowed(identity, "*", None) is True and any(
                s.actions == ["*"] and s.resources == ["*"] for s in m.statements(identity) if s.effect == "Allow"
            )
        return m.is_admin(identity)


def _azure_writes(op: str) -> bool:
    """An Azure operation that changes something: a write or delete, or an action that isn't a read in disguise
    (generateUserDelegationKey, listKeys and the like read; listKeys is handled as admin before this)."""
    if op.endswith(("/write", "/delete")):
        return True
    return op.endswith("/action") and not re.search(r"/(get|list|read|generate)[^/]*/action$", op)


def _system_identity(r: graph.Resource) -> bool:
    """A workload that is its own identity: an Azure system-assigned identity, or a Google Cloud workload running as
    the default compute service account."""
    if r.type.startswith("google_"):
        return bool(clouds.system_identity(r.type, r.body))
    if not r.type.startswith("azurerm_"):
        return False
    return any("SystemAssigned" in str(b.get("type", "")) for b in _list(r.body.get("identity")) if isinstance(b, dict))


# a resource type's service (google_<service>_…) → the prefix of its permissions, where they differ
_GCP_PERMISSION_SERVICE = {"firestore": "datastore", "sql": "cloudsql"}
IMPLIED = "automatic roles/editor grant (default compute service account)"
# a Google OAuth access scope (its alias, or the tail of its URL) → the permissions a token with it may use
_SCOPES = {
    "compute": ["compute.*"],
    "compute-rw": ["compute.*"],
    "compute-ro": ["compute.*.get", "compute.*.list"],
    "compute.readonly": ["compute.*.get", "compute.*.list"],
    "storage-full": ["storage.*"],
    "storage-rw": ["storage.*"],
    "devstorage.full_control": ["storage.*"],
    "devstorage.read_write": ["storage.*"],
    "storage-ro": ["storage.*.get", "storage.*.list"],
    "devstorage.read_only": ["storage.*.get", "storage.*.list"],
    "datastore": ["datastore.*"],
    "sql-admin": ["cloudsql.*"],
    "sqlservice.admin": ["cloudsql.*"],
    "bigquery": ["bigquery.*"],
    "pubsub": ["pubsub.*"],
    "cloud-source-repos": ["source.*"],
}


def _matches(act: str, patterns: list[str] | frozenset[str]) -> bool:
    return any(fnmatch.fnmatchcase(act, p) for p in patterns)
