"""If these credentials leak: what an attacker holding one identity's credentials can become and reach.

From a start identity whose credentials the attacker holds (an AWS IAM user or role, an Azure managed identity or a
workload's system-assigned one, a Google Cloud service account), repeat until nothing changes:

- **grants**: the data stores its own permissions reach, at their access level (`iam.Models.access`: AWS
  statements, Azure role assignments, Google Cloud IAM bindings, at their scope);
- **identities it can become**: an AWS role whose trust policy names it (or the account root, when its own policies
  allow sts:AssumeRole), a Google Cloud service account it can act as (token creator, service account user);
- **techniques**: every privilege-escalation, lateral-movement and credential-source rule of the knowledge base
  for its cloud (AWS actions, Azure operations, Google Cloud permissions) that it's allowed on a resource of the
  rule's type. The rule's attribute tests must hold, and an AWS trust it names in prose ("a role whose trust policy
  lets lambda.amazonaws.com assume it") is checked against the role. What the rule gives is gained: a resource's identity (a passed role, a function's role), the account
  (escalates: self), data access, or control of a compute resource's input (its identity, possibly);
- **credentials in data**: a resource it can read whose configuration holds an access key gives the key's user.

Every gain records the hop that justified it (the rule id and why) and how sure it is; an identity with every
action on every resource is the account's administrator and reaches everything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from terrahunter import arch, conditions, graph, iam, kb

CONF = {"certain": 0, "likely": 1, "possible": 2}
# an SSH private key held in configuration: a generated key's private half, a key file, PEM text
_PRIVATE_KEY = re.compile(
    r"tls_private_key\.[^.]+\.private_key|PRIVATE KEY|private[-_]?key|id_(rsa|ed25519)\b", re.IGNORECASE
)
# user data that gives a login a password, or turns password logins on
_PASSWORD_LOGIN = re.compile(r"chpasswd|\bpasswd\b|PasswordAuthentication\s+yes", re.IGNORECASE)
_TRUST = re.compile(r"trust policy (?:lets|allows) ([a-z0-9.-]+\.amazonaws\.com)")
MAX_ROUNDS = 8


@dataclass
class Gain:
    kind: str  # identity | data | control | admin
    address: str
    via: str  # the identity it was gained from
    rule: str  # technique id, or grant / assume / credentials
    text: str
    confidence: str
    access: str = ""  # data: admin | write | read | list


@dataclass
class Result:
    start: str
    gains: dict[tuple[str, str], Gain] = field(default_factory=dict)  # (kind, address) → how it was first gained

    def identities(self) -> list[str]:
        return [a for (k, a) in self.gains if k == "identity"]

    def data(self) -> dict[str, str]:
        return {a: g.access for (k, a), g in self.gains.items() if k == "data"}

    def path(self, kind: str, address: str) -> list[Gain]:
        """The hops from the start to a gain, in order."""
        out, seen = [], set()
        g = self.gains.get((kind, address))
        while g and (g.kind, g.address) not in seen:
            seen.add((g.kind, g.address))
            out.append(g)
            g = self.gains.get(("identity", g.via)) if g.via != self.start else None
        return list(reversed(out))


def _service(rtype: str) -> str:
    from terrahunter import chains  # the IAM service a data store's actions belong to

    for svc, types in chains.SERVICE_SINKS.items():
        if rtype in types:
            return svc
    return chains.kb_service(rtype)


def _attr_ok(tests: list[dict], body: dict) -> bool | None:
    """A technique's attribute tests on its target: equals, not_equals, in, contains, present."""
    out: bool | None = True
    for t in tests or []:
        vals = [conditions.scalar(v) for v in conditions.values(body, t["attr"].split("."))]
        known = [v for v in vals if v is not conditions._UNKNOWN]
        if "present" in t:
            r: bool | None = bool(vals) == bool(t["present"])
        elif not known:
            r = None if vals else ("not_equals" in t)
        elif "equals" in t:
            r = any(conditions._canon(v) == conditions._canon(t["equals"]) for v in known)
        elif "not_equals" in t:
            r = all(conditions._canon(v) != conditions._canon(t["not_equals"]) for v in known)
        elif "in" in t:
            r = any(conditions._canon(v) in {conditions._canon(x) for x in t["in"]} for v in known)
        elif "contains" in t:
            r = any(conditions._canon(v) == conditions._canon(t["contains"]) for v in known)
        else:
            r = True
        if r is False:
            return False
        if r is None:
            out = None
    return out


def _min(*confs: str) -> str:
    return max(confs, key=lambda c: CONF[c])


def search(g: graph.Graph, model: arch.Model, start: str, im: iam.Models | None = None) -> Result:
    im = im or iam.Models(g)
    R = g.resources
    res = Result(start)
    runs_as: dict[str, list[str]] = {}
    for c in model.connections:
        if c.label == "runs as":
            runs_as.setdefault(c.source, []).append(c.target)
    stores = [a for a, r in R.items() if r.mode == "managed" and _is_store(r.type)]
    roles = [a for a, r in R.items() if r.mode == "managed" and r.type == "aws_iam_role"]
    kinds = ("privesc", "lateral", "credential-source")
    rules_by = {c: [r for r in kb.techniques(c) if r.get("kind") in kinds] for c in ("aws", "azure", "gcp")}
    by_type: dict[str, list[str]] = {}
    for a, r in R.items():
        if r.mode == "managed":
            by_type.setdefault(r.type, []).append(a)
    conf_of: dict[str, str] = {start: "certain"}
    # the stores a resource policy opens to any AWS account (any signed-in principal, the start's too)
    public = {
        c: next(w for w, _ in v if "any AWS account" in w)
        for c, v in model.exposed.items()
        if c in R and _is_store(R[c].type) and any("any AWS account" in w for w, _ in v)
    }
    public |= {c: v[0][0] for c, v in model.account_open.items() if c in R and v}

    def gain(kind, address, via, rule, text, confidence, access="") -> bool:
        key = (kind, address)
        old = res.gains.get(key)
        if old is not None and (
            CONF[old.confidence] < CONF[confidence]
            or CONF[old.confidence] == CONF[confidence]
            and (kind != "data" or iam.LEVELS.get(old.access, 0) >= iam.LEVELS.get(access, 0))
        ):
            return False
        res.gains[key] = Gain(kind, address, via, rule, text, confidence, access)
        if kind == "identity":
            conf_of[address] = _min(confidence, conf_of.get(address, confidence)) if old else confidence
        return True

    def allowed(who: str, action: str, target: str | None) -> bool | None:
        if not R[who].type.startswith("aws_"):  # Azure operations, Google Cloud permissions: at the target's scope
            return im.allowed(who, action, target)
        svc = action.split(":")[0].lower()
        on_it = im.allowed(who, action, target) if target is not None else False
        if target is None or _service(R[target].type) != svc and not R[target].type.startswith(f"aws_{svc}"):
            # an action of another service: on a new resource (lambda:CreateFunction), or acting on this one
            # (ssm:StartSession on an instance): whichever its statements allow
            anywhere = im.allowed(who, action, None)
            return True if True in (on_it, anywhere) else None if None in (on_it, anywhere) else False
        return on_it

    def implied(who: str, action: str, target: str | None) -> bool:
        """Allowed only by a grant the cloud adds by default (the default compute account's Editor role), not one
        in the configuration: someone may have taken it away."""
        return not R[who].type.startswith("aws_") and im.why(who, action, target).startswith(iam.IMPLIED)

    comps = {c.id: c for c in model.components}
    compute = [c for c in comps if c in R and (kb.entry(R[c].type) or {}).get("category") == "compute"]
    identity_types = ("aws_iam_role", "aws_iam_user", "azurerm_user_assigned_identity", "google_service_account")

    def identity_of(t: str) -> list[str]:
        """The identity a resource gives whoever controls it: itself for a role, else what it runs as."""
        if R[t].type in identity_types:
            return [t]
        own = [t] if iam._system_identity(R[t]) else []  # an Azure workload's system-assigned identity
        return own + runs_as.get(t, [])

    def _apply(rule: dict, who: str, base: str, admin: bool) -> bool:
        req = rule.get("requires") or {}
        acts = req.get("actions") or []
        any_of = req.get("any_of_actions") or []
        on = req.get("on")
        types = on if isinstance(on, list) else [on] if on else []
        if rule["id"] == "privesc-sts-001" or not (acts or any_of):
            return False  # assuming roles is handled with the trust; a rule needing no action is an exposure
        services = {m.group(1) for c in req.get("conditions") or [] for m in [_TRUST.search(c)] if m}
        becomes = rule.get("becomes") or {}
        changed = False
        for t in [x for ty in types for x in by_type.get(ty, [])] or ([None] if not types else []):
            if t == who:
                continue
            oks = [True if admin else allowed(who, a, t) for a in acts]
            if any_of:
                alts = [[True if admin else allowed(who, a, t) for a in alt] for alt in any_of]
                best = (
                    True
                    if any(all(x is True for x in alt) for alt in alts)
                    else (None if any(all(x is not False for x in alt) for alt in alts) else False)
                )
                oks.append(best)
            if any(x is False for x in oks):
                continue
            conf = base if all(x is True for x in oks) else _min(base, "possible")
            if not admin and any(implied(who, a, t) for a in acts):
                conf = _min(conf, "likely")
            if t is not None:
                ok = _attr_ok(req.get("attributes"), R[t].body)
                if ok is False:
                    continue
                if ok is None:
                    conf = _min(conf, "likely")
                if services and R[t].type == "aws_iam_role" and not (services & im.services(t)):
                    continue  # the role doesn't trust the service the technique passes it to
            title = rule.get("title") or rule["id"]
            if becomes.get("escalates") == "self":
                changed |= gain(
                    "admin", "account", who, rule["id"], f"{who}: {title} (rewrites its own permissions)", conf
                )
            if t is None:
                continue
            idt = becomes.get("identity_of")
            if idt:
                if t in comps and (kb.entry(R[t].type) or {}).get("category") == "compute":  # it runs their code
                    changed |= gain("control", t, who, rule["id"], f"{who}: {title} on {t}", conf)
                for ident in identity_of(t):
                    changed |= gain("identity", ident, who, rule["id"], f"{who}: {title} on {t} gives {ident}", conf)
            da = becomes.get("data_access")
            if da:
                changed |= gain("data", t, who, rule["id"], f"{who}: {title} on {t}", conf, da.get("access", "read"))
            ci = becomes.get("controls_input_of")
            if ci:
                for e in g.edges:  # the compute this resource feeds (a queue's function, a topic's subscriber)
                    other = e.source if e.target == t else e.target if e.source == t else None
                    if other and R.get(other) and R[other].type == ci:
                        changed |= gain("control", other, who, rule["id"], f"{who}: {title} on {t} feeds {other}", conf)
                        for ident in identity_of(other):
                            changed |= gain(
                                "identity",
                                ident,
                                who,
                                rule["id"],
                                f"{other} runs as {ident}: input the attacker sends is code it may run",
                                _min(conf, "possible"),
                            )
        return changed

    keys = held_keys(g)  # a resource → the users whose access keys it holds

    def _keys_in(addr: str) -> list[str]:
        return list(dict.fromkeys(keys.get(addr, [])))

    # SSH from the internet with credentials found in data: instances with a public IP and port 22 open

    def ssh_open(inst: str) -> bool:
        c = comps.get(inst)
        if c is None:
            return False
        ports = [p.strip() for b in c.badges if b.text.startswith("open to internet: ") for p in b.text[18:].split(",")]
        return any(p in ("22", "all") for p in ports) and any(b.text == "public IP" for b in c.badges)

    instances = [a for a in by_type.get("aws_instance", []) if ssh_open(a)]
    keyed = [a for a in instances if R[a].body.get("key_name")]
    private_keys = [  # where a private key is kept: a parameter, a secret, an object (not the generator itself)
        a
        for a, r in R.items()
        if r.mode == "managed"
        and r.type != "tls_private_key"
        and _PRIVATE_KEY.search(f"{r.name} {r.body.get('value', '')} {r.body.get('secret_string', '')}")
    ]
    passworded = [a for a in instances if _PASSWORD_LOGIN.search(str(R[a].body.get("user_data", "")))]

    def can_read(who: str, addr: str, admin: bool) -> bool:
        gn = res.gains.get(("data", addr))
        if admin or gn and iam.LEVELS.get(gn.access, 0) >= iam.LEVELS["read"]:
            return True
        return iam.LEVELS.get(im.access(who, addr, _service(R[addr].type)), 0) >= iam.LEVELS["read"]

    def shell(who: str, inst: str, how: str, rule: str, conf: str) -> bool:
        changed = gain("control", inst, who, rule, f"{who}: {how}, and SSH to {inst} is open: a shell on it", conf)
        for ident in identity_of(inst):
            text = f"{inst} runs as {ident}: from the shell, its credentials come from the instance metadata service"
            changed |= gain("identity", ident, who, rule, text, conf)
        return changed

    for _ in range(MAX_ROUNDS):
        changed = False
        for who in list(conf_of):
            base = conf_of[who]
            admin = im.is_admin(who)
            if admin and gain(
                "admin", "account", who, "grant", f"{who} is allowed every action on every resource", base
            ):
                changed = True
            # grants: the data its own statements reach
            for s in [x for x in stores if R[x].type.split("_")[0] == R[who].type.split("_")[0]]:
                level = "admin" if admin else im.access(who, s, _service(R[s].type))
                if level:
                    if R[who].type.startswith("google_"):
                        src = im.gcp.access_via(who, s)[1] or who
                    else:
                        src = im.why(who, f"{_service(R[s].type)}:*", s) or who
                    conf = _min(base, "likely") if src.startswith(iam.IMPLIED) else base
                    changed |= gain("data", s, who, "grant", f"{who} grants {level} on {s} ({src})", conf, level)
            # compute its own statements give every action on (ec2:* on an instance, lambda:* on a function): it
            # can rewrite what runs there
            for x in compute:
                if (
                    not admin
                    and x != who
                    and R[x].type.startswith("aws_")
                    and im.access(who, x, _service(R[x].type)) == "admin"
                ):
                    changed |= gain("data", x, who, "grant", f"{who} grants every action on {x}", base, "admin")
            # stores whose own resource policy lets any AWS account in
            for s, why in public.items():
                changed |= gain("data", s, who, "resource-policy", f"{s}: {why}, so {who} can too", base, "read")
            # roles it can assume
            for role in roles:
                if role == who:
                    continue
                ok = True if admin else im.can_assume(who, role)
                if ok is not False:
                    conf = base if ok else _min(base, "possible")
                    changed |= gain("identity", role, who, "privesc-sts-001", f"{who} can assume {role}", conf)
            # the knowledge base's techniques
            cloud = (
                "azure" if R[who].type.startswith("azurerm_") else "gcp" if R[who].type.startswith("google_") else "aws"
            )
            for rule in rules_by[cloud]:
                changed |= _apply(rule, who, base, admin)
            # an SSH private key or a login password it can read, for an instance that accepts SSH from anywhere
            for k in private_keys:
                if keyed and can_read(who, k, admin):
                    for inst in keyed:
                        changed |= shell(
                            who,
                            inst,
                            f"{k} holds an SSH private key it can read",
                            "ssh-found-key",
                            _min(base, "likely"),
                        )
            for inst in passworded:
                if can_read(who, inst, admin):
                    how = "the instance's user data, which it can read, sets a login password"
                    changed |= shell(who, inst, how, "ssh-found-password", _min(base, "likely"))
            # credentials in configuration it can read: a resource that holds an access key (an environment's
            # settings, a function's variables) gives the key's user to whoever can read the resource
            for addr in keys:
                svc = _service(R[addr].type)
                readable = admin or iam.LEVELS.get(im.access(who, addr, svc), 0) >= iam.LEVELS["read"]
                gn = res.gains.get(("data", addr))
                readable = readable or bool(gn and iam.LEVELS.get(gn.access, 0) >= iam.LEVELS["read"])
                held = ("control", addr) in res.gains  # a shell on a machine reads the files put there
                if readable or held:
                    how = "controls it" if held and not readable else "can read it"
                    for user in _keys_in(addr):
                        text = f"{addr} holds an access key of {user}, and {who} {how}"
                        changed |= gain("identity", user, who, "credentials", text, _min(base, "likely"))
        if not changed:
            break
    if ("admin", "account") in res.gains:  # the administrator reaches everything: data, and IAM itself
        g0 = res.gains[("admin", "account")]
        iam_types = ("aws_iam_policy", "aws_iam_role", "aws_iam_user", "aws_iam_group")
        prefix = R[g0.via].type.split("_")[0] + "_"
        # its cloud's data, IAM, and every component on the diagram: compute, identities, the project itself
        owned = stores + [a for t in iam_types for a in by_type.get(t, [])]
        owned += [c.id for c in model.components if c.type.startswith(prefix) and not c.unknown]
        owned += [
            a
            for a, r in R.items()
            if r.mode == "managed"
            and re.search(r"^(azurerm_role_assignment|google_project|google_project_iam_\w+)$", r.type)
        ]
        # and the data kept inside them that isn't drawn: documents, objects, secret versions
        owned += [a for a, r in R.items() if r.mode == "managed" and (kb.entry(r.type) or {}).get("category") == "data"]
        for s in dict.fromkeys(x for x in owned if R[x].type.startswith(prefix)):
            gain("data", s, g0.via, "admin", f"{g0.via} is the account's administrator", g0.confidence, "admin")
    return res


_ACCESS_KEY = re.compile(r"\baws_iam_access_key\.([\w-]+)")


def held_keys(g: graph.Graph) -> dict[str, list[str]]:
    """The users whose access keys each resource holds: its configuration references the key (a function's
    variables, an environment's settings), or a deploy-time provisioner puts it there (a file copied to a machine)."""
    R = g.resources
    owner = {
        k: [x.target for x in g.edges if x.source == k and R.get(x.target) and R[x.target].type == "aws_iam_user"]
        for k, r in R.items()
        if r.type == "aws_iam_access_key"
    }
    out: dict[str, list[str]] = {}
    for e in g.edges:
        if e.target in owner and e.source in R:
            out.setdefault(e.source, []).extend(owner[e.target])
    for a, r in R.items():
        prefix = f"{r.module}." if r.module else ""
        for name in _ACCESS_KEY.findall(str(r.body.get("provisioner") or "")):
            out.setdefault(a, []).extend(owner.get(f"{prefix}aws_iam_access_key.{name}", []))
    return {a: list(dict.fromkeys(u)) for a, u in out.items() if u}


def _is_store(rtype: str) -> bool:
    from terrahunter import chains

    return chains.kb_store(rtype)


SENSITIVE = re.compile(
    r"financ|customer|pii|secret|cred|passw|backup|payment|card|personal|patient|payroll|billing|invoice|flag",
    re.IGNORECASE,
)
RANK = {"critical": 0, "high": 1, "medium": 2}


def _sensitive(r: graph.Resource) -> bool:
    e = kb.entry(r.type) or {}
    return (
        bool(e.get("sensitive_default"))
        or r.type in ("aws_secretsmanager_secret", "aws_ssm_parameter")
        or bool(SENSITIVE.search(r.name))
    )


# a trust principal outside the configuration: another account's root, role or user, any account, a federated
# identity provider (account ids derived from aws_caller_identity are this account)
_OTHER_ACCOUNT = re.compile(r"^(?:arn:aws[\w-]*:iam::)?(\d{12})(?::|$)")
_NARROWING = {  # condition keys that narrow who outside may assume it, and what the attacker would need
    "sts:externalid": "the external ID",
    "aws:principalorgid": "a principal in the organization",
    "aws:principalarn": "a principal whose ARN matches",
    "aws:sourceaccount": "a request from the account",
    "aws:sourcearn": "a request from the resource",
    "aws:principalaccount": "a principal in the account",
}


def _outsiders(im: iam.Models, role: str) -> list[tuple[str, str, str]]:
    """Who outside the configuration a role's trust admits: (who, what narrows it, confidence)."""
    out = []
    for st in im.aws.trust(role):
        conds = {str(k).strip('"').lower() for tests in st.condition.values() if isinstance(tests, dict) for k in tests}
        narrowed = sorted(
            {v for k, v in _NARROWING.items() if k in conds} | ({f"{k}" for k in conds if k.endswith(":sub")})
        )
        for p in st.resources:
            kind, _, value = p.partition(":")
            value = value.strip('"')
            if kind == "AWS" and value == "*":
                who = "any AWS account"
            elif kind == "AWS" and (m := _OTHER_ACCOUNT.match(value)):
                who = f"account {m.group(1)}" + (
                    f" ({value.rsplit(':', 1)[-1]})" if ":" in value and not value.endswith(":root") else ""
                )
            elif kind == "Federated":  # an identity provider: its identities are outside the account
                who = f"identities from {value.rsplit('/', 1)[-1] or value}"
            else:
                continue
            open_to_all = who == "any AWS account" or kind == "Federated" and not any(c.endswith(":sub") for c in conds)
            conf = "certain" if open_to_all and not narrowed else "possible"
            out.append((who, ", ".join(narrowed), conf))
    return out


def outside(g: graph.Graph, model: arch.Model) -> list:
    """From other accounts: each role whose trust policy admits principals outside the configuration (another
    account, any account, a federated identity provider), and what becoming it gives. Worst first."""
    from terrahunter import chains

    im = iam.Models(g)
    R = g.resources
    comps = {c.id for c in model.components}
    out = []
    for role in [a for a, r in R.items() if r.mode == "managed" and r.type == "aws_iam_role"]:
        who = _outsiders(im, role)
        if not who:
            continue
        conf = min((c for _, _, c in who), key=lambda c: CONF[c])
        r = search(g, model, role, im)
        data = r.data()
        stores = sorted(a for a in data if _is_store(R[a].type))
        admin = r.gains.get(("admin", "account"))
        hops = [
            f"{w} may assume {role}" + (f", given {n}" if n else ": nothing in the trust narrows it") for w, n, _ in who
        ]
        hops += [
            g_.text + (f" [{g_.rule}]" if g_.rule not in ("grant", "credentials") else "")
            for g_ in r.gains.values()
            if g_.kind in ("identity", "admin") and g_.address != role
        ][:6]
        if stores:
            hops.append(
                "reaches: "
                + ", ".join(f"{s} ({data[s]})" + (" ⚠sensitive" if _sensitive(R[s]) else "") for s in stores)
            )
        sens = any(_sensitive(R[s]) and iam.LEVELS.get(data[s], 0) >= iam.LEVELS["read"] for s in stores)
        open_ = conf == "certain"
        severity = "critical" if open_ and (admin or sens) else "high" if admin or sens or open_ else "medium"
        names = ", ".join(dict.fromkeys(w for w, _, _ in who))
        ch = chains.Chain(
            severity,
            "from another account",
            conf,
            f"{R[role].name}: {names} may assume it",
            ["attacker-principal", role],
            stores,
            hops,
        )
        ch.controls = [a for (k, a) in r.gains if k in ("identity", "control") and a != role]
        ch.drawn = role in comps
        out.append((RANK[severity], CONF[conf], -len(stores), role, ch))
    return [x[-1] for x in sorted(out, key=lambda x: x[:4])]


def leaks(g: graph.Graph, model: arch.Model, starts: list[str] | None = None):
    """If these credentials leak: for each AWS user and role (or only `starts`), what holding its credentials gives
    an attacker. One path per identity that escalates or reaches data, worst first."""
    from terrahunter import chains

    im = iam.Models(g)
    R = g.resources
    out = []
    for start in starts or im.identities:
        if start not in R:
            continue
        r = search(g, model, start, im)
        data = r.data()
        stores = sorted(a for a in data if _is_store(R[a].type))
        admin = r.gains.get(("admin", "account"))
        gained = [i for i in r.identities() if i != start]
        if not (stores or gained or admin):
            continue
        # the identity it ends as: the administrator, else the one the most data is reached through
        through: dict[str, int] = {}
        for gn in r.gains.values():
            if gn.kind == "data":
                through[gn.via] = through.get(gn.via, 0) + 1
        end = admin.via if admin else max([start, *gained], key=lambda i: (through.get(i, 0), i == start))
        path = r.path("identity", end) if end != start else []
        hops = [f"The attacker holds the credentials of {start}"]
        hops += [f"{h.text}" + (f" [{h.rule}]" if h.rule not in ("grant", "credentials") else "") for h in path]
        if admin:
            hops.append(f"{admin.text}" + (f" [{admin.rule}]" if admin.rule != "grant" else ""))
        conf = _min("certain", *[h.confidence for h in path], *([admin.confidence] if admin else []))
        if stores:
            hops.append(
                "reaches: "
                + ", ".join(f"{s} ({data[s]})" + (" ⚠sensitive" if _sensitive(R[s]) else "") for s in stores)
            )
        sens = any(_sensitive(R[s]) and iam.LEVELS.get(data[s], 0) >= iam.LEVELS["read"] for s in stores)
        severity = "critical" if admin or sens else "high" if stores else "medium"
        what = (
            "becomes the account's administrator"
            if admin
            else f"reaches {len(stores)} data store{'s' if len(stores) != 1 else ''}"
            if stores
            else f"becomes {len(gained)} other identit{'ies' if len(gained) != 1 else 'y'}"
        )
        if gained and not admin:
            what += f" (as {', '.join(h.address.rsplit('.', 1)[-1] for h in path) or start})" if path else ""
        steps = ["attacker-principal", start, *[h.address for h in path]]
        comps = {c.id for c in model.components}
        ch = chains.Chain(severity, "if these credentials leak", conf, f"{R[start].name}: {what}", steps, stores, hops)
        ch.drawn = all(s == "attacker-principal" or s in comps for s in steps)
        out.append((admin is None, RANK[severity], -len(stores), CONF[conf], start, ch))
    return [x[-1] for x in sorted(out, key=lambda x: x[:5])]
