"""Hard-coded secrets and long-lived keys: findings terrahunter makes itself, alongside the scanners'.

A secret is a literal value in an attribute that holds one (a SecureString parameter's value, a secret's string, a
database's master password, a provider's credentials, an environment variable named like a credential). A value
that comes from a variable, a data source or another resource isn't one: its real value is set elsewhere (and an
`ignore_changes` on it keeps it out of the code). Placeholders (`TODO`, `CHANGEME`, `not-a-secret`, `<token>`) and
short values aren't either. The word "example" doesn't make a value a placeholder: AWS's documented example keys are
still credentials in the place real ones go.
"""

from __future__ import annotations

import re

from terrahunter import deps, graph, scanners

# per type: the attributes whose literal value is a secret (dotted paths into blocks)
SECRET_ATTRS = {
    "aws_secretsmanager_secret_version": ["secret_string"],
    "aws_db_instance": ["password"],
    "aws_rds_cluster": ["master_password"],
    "aws_docdb_cluster": ["master_password"],
    "aws_neptune_cluster": ["master_password"],
    "aws_redshift_cluster": ["master_password"],
    "aws_elasticache_replication_group": ["auth_token"],
    "aws_mq_broker": ["user.password"],
    "aws_opensearch_domain": ["advanced_security_options.master_user_options.master_user_password"],
    "aws_iam_user_login_profile": ["password"],
    "azurerm_linux_virtual_machine": ["admin_password"],
    "azurerm_windows_virtual_machine": ["admin_password"],
    "azurerm_virtual_machine": ["os_profile.admin_password"],
    "azurerm_mssql_server": ["administrator_login_password"],
    "azurerm_postgresql_flexible_server": ["administrator_password"],
    "azurerm_mysql_flexible_server": ["administrator_password"],
    "azurerm_key_vault_secret": ["value"],
    "google_sql_user": ["password"],
    "google_secret_manager_secret_version": ["secret_data"],
    "kubernetes_secret": ["data", "string_data"],
}
# provider arguments that are credentials
PROVIDER_ATTRS = ("access_key", "secret_key", "token", "client_secret", "client_certificate_password", "credentials")
# environment-like maps whose entries are credentials when their name says so
ENV_ATTRS = ("environment.variables", "environment", "app_settings", "environment_variables", "env")
_SECRET_NAME = re.compile(r"(passw(or)?d|secret|token|api_?key|access_?key|private_?key|credential)", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r"todo|tbd|change[-_ ]?me|replace[-_ ]?me|placeholder|dummy|redacted|not[-_ ]?a[-_ ]?(real|secret)|fake|"
    r"^x{3,}$|^\*+$|^<[^>]*>$|^\{\{.*\}\}$|set[-_ ]by[-_ ]",
    re.IGNORECASE,
)
MIN_LENGTH = 12


def literal(v) -> str:
    """A value written in the code (not an expression), or ""."""
    s = deps.unquote(v) if isinstance(v, str) else None
    return s if s and "${" not in s else ""


def is_secret(value: str) -> bool:
    """Whether a literal looks like real secret material: long enough, not a placeholder, more than one character."""
    return len(value) >= MIN_LENGTH and not _PLACEHOLDER.search(value) and len(set(value)) > 4


def _at(body: dict, path: str) -> list:
    out = [body]
    for part in path.split("."):
        nxt = []
        for x in out:
            for y in x if isinstance(x, list) else [x]:
                if isinstance(y, dict) and part in y:
                    nxt.append(y[part])
        out = nxt
    return out


def _values(v) -> list[tuple[str, str]]:
    """(key, literal) pairs in a value: a string itself, or a JSON / map's string members (secret_string is often a
    jsonencode of an object)."""
    if isinstance(v, str):
        lit = literal(v)
        return [("", lit)] if lit else []
    if isinstance(v, dict):
        return [(str(k).strip('"'), x) for k, val in v.items() if not k.startswith("__") for _, x in _values(val)]
    if isinstance(v, list):
        return [p for x in v for p in _values(x)]
    return []


def find(g: graph.Graph) -> list[scanners.Finding]:
    R = g.resources
    out: list[scanners.Finding] = []

    def add(fid: str, title: str, sev: str, r: graph.Resource | None, address: str, msg: str, file="", line=0):
        out.append(
            scanners.Finding(
                fid, title, sev, "terrahunter", r.file if r else file, r.line if r else line, address, msg, "", address
            )
        )

    for a, r in R.items():
        if r.mode != "managed":
            continue
        attrs = list(SECRET_ATTRS.get(r.type, []))
        if r.type == "aws_ssm_parameter" and deps.unquote(r.body.get("type")) == "SecureString":
            attrs.append("value")  # a plain String parameter is configuration, whatever it says
        for attr in attrs:
            for v in _at(r.body, attr):
                hits = [
                    (k, x)
                    for k, x in _values(v)
                    if is_secret(x) and (not k or _SECRET_NAME.search(k) or attr != "secret_string")
                ]
                if hits:
                    what = f"{attr}" + (f" ({', '.join(k for k, _ in hits if k)})" if any(k for k, _ in hits) else "")
                    add(
                        "TH-SECRET",
                        f"Hard-coded secret in {what}",
                        "HIGH",
                        r,
                        a,
                        f"{a}: {what} is a literal in the code",
                    )
                    break
        for attr in ENV_ATTRS:
            for v in _at(r.body, attr):
                names = [k for k, x in _values(v) if k and _SECRET_NAME.search(k) and is_secret(x)]
                if names:
                    add(
                        "TH-SECRET",
                        f"Hard-coded secret in {attr} ({', '.join(names[:3])})",
                        "HIGH",
                        r,
                        a,
                        f"{a}: {', '.join(names)} set to literals",
                    )
        if r.type == "aws_iam_access_key" and deps.unquote(r.body.get("status")) != "Inactive":
            add("TH-KEY", "Long-lived access key", "MEDIUM", r, a, f"{a}: an IAM user access key that doesn't expire")
    # provider blocks: credentials written into them
    for mod, d in g.module_dirs.items():
        notes: list[str] = []
        for fname, doc, text in deps.load_dir(d, notes, str(d)):
            for block in doc.get("provider") or []:
                for name, body in block.items() if isinstance(block, dict) else []:
                    name = name.strip('"')
                    for b in body if isinstance(body, list) else [body]:
                        keys = [k for k in PROVIDER_ATTRS if isinstance(b, dict) and is_secret(literal(b.get(k)) or "")]
                        if keys:
                            line = next(
                                (
                                    i
                                    for i, t in enumerate(text.splitlines(), 1)
                                    if re.match(rf'\s*provider\s+"?{name}"?', t)
                                ),
                                0,
                            )
                            where = (f"{mod}." if mod else "") + f"provider.{name}"
                            rel = next(
                                (r.file.rsplit("/", 1)[0] for r in R.values() if r.module == mod and "/" in r.file), ""
                            )
                            add(
                                "TH-SECRET",
                                f"Hard-coded credentials in the {name} provider ({', '.join(keys)})",
                                "HIGH",
                                None,
                                where,
                                f"{where}: {', '.join(keys)} are literals",
                                f"{rel}/{fname}" if rel else fname,
                                line,
                            )
    return out
