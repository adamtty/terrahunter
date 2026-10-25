"""If these credentials leak: what an attacker holding one identity's credentials can become and reach.

From a start identity (an IAM user or role whose credentials the attacker holds), repeat until nothing changes:

- **grants**: the data stores its own statements reach, at their access level (`iam.Model.access`);
- **roles it can assume**: a trust policy that names it, or the account root when its own policies allow
  sts:AssumeRole on the role;
- **techniques**: every AWS privilege-escalation, lateral-movement and credential-source rule of the knowledge
  base whose actions it's allowed on a resource of the rule's type. The rule's attribute tests must hold, and a
  trust it names in prose ("a role whose trust policy lets lambda.amazonaws.com assume it") is checked against the
  role. What the rule gives is gained: a resource's identity (a passed role, a function's role), the account
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


def search(g: graph.Graph, model: arch.Model, start: str, im: iam.Model | None = None) -> Result:
    im = im or iam.Model(g)
    R = g.resources
    res = Result(start)
    runs_as: dict[str, list[str]] = {}
    for c in model.connections:
        if c.label == "runs as":
            runs_as.setdefault(c.source, []).append(c.target)
    stores = [a for a, r in R.items() if r.mode == "managed" and _is_store(r.type)]
    roles = [a for a, r in R.items() if r.mode == "managed" and r.type == "aws_iam_role"]
    rules = [r for r in kb.techniques("aws") if r.get("kind") in ("privesc", "lateral", "credential-source")]
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
        svc = action.split(":")[0].lower()
        if target is not None and _service(R[target].type) != svc and not R[target].type.startswith(f"aws_{svc}"):
            target = None  # an action on a new resource (lambda:CreateFunction): on any resource
        if target is None:
            return im.allowed(who, action, None)
        return im.allowed(who, action, target)

    def identity_of(t: str) -> list[str]:
        """The identity a resource gives whoever controls it: itself for a role, else what it runs as."""
        return [t] if R[t].type in ("aws_iam_role", "aws_iam_user") else runs_as.get(t, [])

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

    keys: dict[str, list[str]] = {}  # a resource → the users whose access keys its configuration holds
    for e in g.edges:
        if R.get(e.target) and R[e.target].type == "aws_iam_access_key" and e.source in R:
            keys.setdefault(e.source, []).extend(
                x.target
                for x in g.edges
                if x.source == e.target and R.get(x.target) and R[x.target].type == "aws_iam_user"
            )

    def _keys_in(addr: str) -> list[str]:
        return list(dict.fromkeys(keys.get(addr, [])))

    # SSH from the internet with credentials found in data: instances with a public IP and port 22 open
    comps = {c.id: c for c in model.components}

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
            admin = im.allowed(who, "*", None) is True and any(
                s.actions == ["*"] and s.resources == ["*"] for s in im.statements(who) if s.effect == "Allow"
            )
            if admin and gain(
                "admin", "account", who, "grant", f"{who} is allowed every action on every resource", base
            ):
                changed = True
            # grants: the data its own statements reach
            for s in stores:
                level = "admin" if admin else im.access(who, s, _service(R[s].type))
                if level:
                    src = im.why(who, f"{_service(R[s].type)}:*", s) or who
                    changed |= gain("data", s, who, "grant", f"{who} grants {level} on {s} ({src})", base, level)
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
            for rule in rules:
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
                if readable:
                    for user in _keys_in(addr):
                        text = f"{addr} holds an access key of {user}, and {who} can read it"
                        changed |= gain("identity", user, who, "credentials", text, _min(base, "likely"))
        if not changed:
            break
    if ("admin", "account") in res.gains:  # the administrator reaches everything: data, and IAM itself
        g0 = res.gains[("admin", "account")]
        iam_types = ("aws_iam_policy", "aws_iam_role", "aws_iam_user", "aws_iam_group")
        for s in stores + [a for t in iam_types for a in by_type.get(t, [])]:
            gain("data", s, g0.via, "admin", f"{g0.via} is the account's administrator", g0.confidence, "admin")
    return res


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


def leaks(g: graph.Graph, model: arch.Model, starts: list[str] | None = None):
    """If these credentials leak: for each AWS user and role (or only `starts`), what holding its credentials gives
    an attacker. One path per identity that escalates or reaches data, worst first."""
    from terrahunter import chains

    im = iam.Model(g)
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
