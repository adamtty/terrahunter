"""What terrahunter knows about Azure and Google Cloud, next to the AWS knowledge in `arch` and `chains`.

The same model for each cloud:

- **containers**: the cloud (an AWS region, an Azure subscription, a GCP project), its networks (VPC, VNet, VPC
  network) and their subnets, an area for services outside any network, and one for identities;
- **exposure**: what the internet reaches on a component and the resource that opens it: a security group (AWS), a
  network security group on the NIC or the subnet (Azure), a firewall rule on the network, matched by target tags
  (GCP); a database firewall rule admitting every address; a public container or bucket binding; a public IP;
- **identities**: what a workload runs as (an IAM role, a managed identity, a service account, or GCP's default
  compute service account) and what its role assignments or IAM bindings reach, by service and by scope.

Roles and their permissions come from the knowledge base; what's here is the exposure logic terrahunter judges itself.
"""

from __future__ import annotations

import re

from terrahunter import deps

COMPONENTS = {
    # Azure
    "azurerm_linux_virtual_machine": ("VM", "compute", "Linux VM"),
    "azurerm_windows_virtual_machine": ("VM", "compute", "Windows VM"),
    "azurerm_virtual_machine": ("VM", "compute", "virtual machine"),
    "azurerm_linux_virtual_machine_scale_set": ("VMSS", "compute", "VM scale set"),
    "azurerm_windows_virtual_machine_scale_set": ("VMSS", "compute", "VM scale set"),
    "azurerm_app_service": ("APP", "compute", "App Service"),
    "azurerm_linux_web_app": ("APP", "compute", "web app"),
    "azurerm_windows_web_app": ("APP", "compute", "web app"),
    "azurerm_function_app": ("FN", "compute", "Function App"),
    "azurerm_linux_function_app": ("FN", "compute", "Function App"),
    "azurerm_windows_function_app": ("FN", "compute", "Function App"),
    "azurerm_container_group": ("ACI", "containers", "container instance"),
    "azurerm_kubernetes_cluster": ("AKS", "containers", "AKS cluster"),
    "azurerm_application_gateway": ("AGW", "network", "application gateway"),
    "azurerm_lb": ("LB", "network", "load balancer"),
    "azurerm_storage_account": ("ST", "storage", "storage account"),
    "azurerm_managed_disk": ("DISK", "storage", "managed disk"),
    "azurerm_key_vault": ("KV", "security", "key vault"),
    "azurerm_sql_server": ("SQL", "database", "SQL server"),
    "azurerm_mssql_server": ("SQL", "database", "SQL server"),
    "azurerm_mysql_server": ("MY", "database", "MySQL server"),
    "azurerm_mysql_flexible_server": ("MY", "database", "MySQL server"),
    "azurerm_postgresql_server": ("PG", "database", "PostgreSQL server"),
    "azurerm_postgresql_flexible_server": ("PG", "database", "PostgreSQL server"),
    "azurerm_cosmosdb_account": ("COS", "database", "Cosmos DB account"),
    "azurerm_user_assigned_identity": ("ID", "security", "managed identity"),
    # Google Cloud
    "google_compute_instance": ("GCE", "compute", "Compute Engine VM"),
    "google_compute_instance_template": ("TPL", "compute", "instance template"),
    "google_cloud_run_service": ("RUN", "compute", "Cloud Run service"),
    "google_cloud_run_v2_service": ("RUN", "compute", "Cloud Run service"),
    "google_cloudfunctions_function": ("FN", "compute", "Cloud Function"),
    "google_cloudfunctions2_function": ("FN", "compute", "Cloud Function"),
    "google_container_cluster": ("GKE", "containers", "GKE cluster"),
    "google_container_node_pool": ("NP", "containers", "GKE node pool"),
    "google_storage_bucket": ("GCS", "storage", "Cloud Storage bucket"),
    "google_compute_disk": ("PD", "storage", "persistent disk"),
    "google_sql_database_instance": ("SQL", "database", "Cloud SQL instance"),
    "google_bigquery_dataset": ("BQ", "analytics", "BigQuery dataset"),
    "google_secret_manager_secret": ("SM", "security", "secret"),
    "google_kms_crypto_key": ("KMS", "security", "KMS key"),
    "google_service_account": ("SA", "security", "service account"),
}
NETWORKS = {"aws_vpc": "VPC", "azurerm_virtual_network": "VNet", "google_compute_network": "VPC network"}
SUBNETS = {
    "aws_subnet": "cidr_block",
    "azurerm_subnet": "address_prefixes",
    "google_compute_subnetwork": "ip_cidr_range",
}
NETWORK_CIDR = {"aws_vpc": "cidr_block", "azurerm_virtual_network": "address_space"}
VMS = {
    "aws_instance",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "azurerm_virtual_machine",
    "google_compute_instance",
    "google_container_node_pool",  # its nodes are Compute Engine instances
}
WEB_APPS = {  # on the internet unless restricted
    "azurerm_app_service",
    "azurerm_linux_web_app",
    "azurerm_windows_web_app",
    "azurerm_function_app",
    "azurerm_linux_function_app",
    "azurerm_windows_function_app",
}
SERVERLESS = {  # on the internet when anyone may invoke them
    "google_cloud_run_service",
    "google_cloud_run_v2_service",
    "google_cloudfunctions_function",
    "google_cloudfunctions2_function",
}
# service key → the data stores it reaches (the AWS ones are in chains.SERVICE_SINKS)
SERVICE_SINKS = {
    "azure-storage": {"azurerm_storage_account"},
    "azure-keyvault": {"azurerm_key_vault"},
    "azure-sql": {"azurerm_sql_server", "azurerm_mssql_server"},
    "azure-db": {
        "azurerm_mysql_server",
        "azurerm_mysql_flexible_server",
        "azurerm_postgresql_server",
        "azurerm_postgresql_flexible_server",
    },
    "azure-cosmos": {"azurerm_cosmosdb_account"},
    "azure-disk": {"azurerm_managed_disk"},
    "gcs": {"google_storage_bucket"},
    "cloudsql": {"google_sql_database_instance"},
    "gcp-secrets": {"google_secret_manager_secret"},
    "bigquery": {"google_bigquery_dataset"},
    "gcp-disk": {"google_compute_disk"},
}
AZURE_ACTIONS = [  # a role's action or data action (built-in roles from the knowledge base, custom ones) → service
    (re.compile(r"^\*$"), "*"),
    (re.compile(r"^Microsoft\.Storage/", re.IGNORECASE), "azure-storage"),
    (re.compile(r"^Microsoft\.KeyVault/", re.IGNORECASE), "azure-keyvault"),
    (re.compile(r"^Microsoft\.Sql/", re.IGNORECASE), "azure-sql"),
    (re.compile(r"^Microsoft\.DBfor(MySQL|PostgreSQL)/", re.IGNORECASE), "azure-db"),
    (re.compile(r"^Microsoft\.DocumentDB/", re.IGNORECASE), "azure-cosmos"),
    (re.compile(r"^Microsoft\.Compute/disks/", re.IGNORECASE), "azure-disk"),
]
GCP_PERMISSIONS = [  # a predefined role's permission (from the knowledge base) → the data it reads
    ("storage.objects.", "gcs"),
    ("cloudsql.", "cloudsql"),
    ("secretmanager.versions.access", "gcp-secrets"),
    ("bigquery.tables.getData", "bigquery"),
    ("compute.disks.", "gcp-disk"),
]
GCP_IAM = {  # binding type → the attribute naming the resource it's on ("" = the project)
    "google_project_iam_member": "",
    "google_project_iam_binding": "",
    "google_storage_bucket_iam_member": "bucket",
    "google_storage_bucket_iam_binding": "bucket",
    "google_secret_manager_secret_iam_member": "secret_id",
    "google_secret_manager_secret_iam_binding": "secret_id",
    "google_bigquery_dataset_iam_member": "dataset_id",
    "google_bigquery_dataset_iam_binding": "dataset_id",
    "google_cloud_run_service_iam_member": "service",
    "google_cloud_run_service_iam_binding": "service",
    "google_cloud_run_v2_service_iam_member": "name",
    "google_cloud_run_v2_service_iam_binding": "name",
    "google_cloudfunctions_function_iam_member": "cloud_function",
    "google_cloudfunctions_function_iam_binding": "cloud_function",
    "google_cloudfunctions2_function_iam_member": "cloud_function",
    "google_cloudfunctions2_function_iam_binding": "cloud_function",
}
PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
INTERNET = {"*", "internet", "any", "0.0.0.0/0", "::/0", "0.0.0.0"}  # noqa: S104 - addresses read, not bound
DB_FIREWALLS = {
    "azurerm_sql_firewall_rule",
    "azurerm_mssql_firewall_rule",
    "azurerm_mysql_firewall_rule",
    "azurerm_mysql_flexible_server_firewall_rule",
    "azurerm_postgresql_firewall_rule",
    "azurerm_postgresql_flexible_server_firewall_rule",
}


def cloud(rtype: str) -> str:
    return next((c for c, p in (("aws", "aws_"), ("azure", "azurerm_"), ("gcp", "google_")) if rtype.startswith(p)), "")


AREAS = {  # cloud → (its container, its services area, its identities area), with their labels
    "aws": (("region", "AWS region"), ("regional", "Regional services"), ("global", "IAM (global)")),
    "azure": (("azure", "Azure subscription"), ("azure-services", "Azure services"), ("azure-identity", "Identities")),
    "gcp": (
        ("gcp", "Google Cloud project"),
        ("gcp-services", "Google Cloud services"),
        ("gcp-iam", "Service accounts"),
    ),
}


def _s(v) -> str:
    u = deps.unquote(v)
    return u if u is not None else (str(v) if v is not None else "")


def _list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def _block(body: dict, key: str) -> dict:
    b = _list(body.get(key))
    return b[0] if b and isinstance(b[0], dict) else {}


def port_range(text: str) -> str:
    """'22-22' → '22', '*' / '0-65535' → 'all', '80-90' → '80-90'."""
    t = text.strip()
    if t in ("*", "", "0-65535", "1-65535"):
        return "all"
    a, _, b = t.partition("-")
    return a if not b or a == b else t


def exposure(R: dict, targets, sources, of) -> tuple[dict[str, list[tuple[str, str]]], dict[str, str]]:
    """Azure and GCP: component → [(port or reason, the resource that opens it)], and component → why it has a
    public IP. `targets(addr, *types, attr=)`, `sources(addr, *types)` and `of(*types)` walk the graph."""
    exposed: dict[str, list[tuple[str, str]]] = {}
    public_ip: dict[str, str] = {}

    # Azure: network security groups, on a NIC or on the subnet
    nsg_open: dict[str, list[tuple[str, str]]] = {nsg: [] for nsg in of("azurerm_network_security_group")}
    rules = [(nsg, r, nsg) for nsg in nsg_open for r in _list(R[nsg].body.get("security_rule")) if isinstance(r, dict)]
    rules += [
        (t, R[r].body, r)
        for r in of("azurerm_network_security_rule")
        for t in targets(r, "azurerm_network_security_group")
    ]
    for nsg, rule, origin in rules:
        if _s(rule.get("direction")).lower() != "inbound" or _s(rule.get("access")).lower() != "allow":
            continue
        srcs = [
            _s(x).lower() for x in _list(rule.get("source_address_prefix")) + _list(rule.get("source_address_prefixes"))
        ]
        if not any(x in INTERNET for x in srcs):
            continue
        ports = [_s(x) for x in _list(rule.get("destination_port_range")) + _list(rule.get("destination_port_ranges"))]
        nsg_open[nsg] += [(port_range(p), origin) for p in ports or ["*"]]
    nic_nsgs: dict[str, set[str]] = {}
    for a in of("azurerm_network_interface_security_group_association"):
        for nic in targets(a, "azurerm_network_interface"):
            nic_nsgs.setdefault(nic, set()).update(targets(a, "azurerm_network_security_group"))
    subnet_nsgs: dict[str, set[str]] = {}
    for a in of("azurerm_subnet_network_security_group_association"):
        for sn in targets(a, "azurerm_subnet"):
            subnet_nsgs.setdefault(sn, set()).update(targets(a, "azurerm_network_security_group"))
    for vm in of(*(t for t in VMS if t.startswith("azurerm_"))):
        nics = targets(vm, "azurerm_network_interface")
        nsgs = set().union(*(nic_nsgs.get(n, set()) for n in nics)) if nics else set()
        nsgs |= {x for n in nics for x in targets(n, "azurerm_network_security_group")}  # the older inline link
        nsgs |= {x for n in nics for sn in targets(n, "azurerm_subnet") for x in subnet_nsgs.get(sn, set())}
        opened = [x for nsg in sorted(nsgs) for x in nsg_open.get(nsg, [])]
        if opened:
            exposed[vm] = opened
        for n in nics:
            if targets(n, "azurerm_public_ip"):
                public_ip[vm] = "public IP on its network interface"

    # GCP: firewall rules on the network, matched by target tags (none: every instance in the network)
    fw: list[tuple[str, list[str], set[str], str]] = []  # (network, ports, target tags, rule)
    for r in of("google_compute_firewall"):
        b = R[r].body
        if _s(b.get("direction") or "INGRESS").upper() != "INGRESS" or _s(b.get("disabled")).lower() == "true":
            continue
        if not any(_s(x) in ("0.0.0.0/0", "::/0") for x in _list(b.get("source_ranges"))):
            continue
        ports = []
        for allow in _list(b.get("allow")):
            if isinstance(allow, dict):
                ps = [_s(p) for p in _list(allow.get("ports"))]
                ports += [port_range(p) for p in ps] if ps else ["all"]
        tags = {_s(t) for t in _list(b.get("target_tags"))}
        for net in targets(r, "google_compute_network"):
            fw.append((net, ports, tags, r))
    for inst in of("google_compute_instance"):
        b = R[inst].body
        nets = set(targets(inst, "google_compute_network"))
        nets |= {n for sn in targets(inst, "google_compute_subnetwork") for n in targets(sn, "google_compute_network")}
        tags = {_s(t) for t in _list(b.get("tags"))}
        opened = [(p, r) for net, ports, want, r in fw if net in nets and (not want or want & tags) for p in ports]
        if opened:
            exposed[inst] = opened
        if any(isinstance(ni, dict) and "access_config" in ni for ni in _list(b.get("network_interface"))):
            public_ip[inst] = "external IP (access_config)"
    # GKE node pools: the nodes are instances in the cluster's network, with external IPs unless the nodes are private
    for pool in of("google_container_node_pool"):
        b = R[pool].body
        clusters = targets(pool, "google_container_cluster")
        nets = {n for c in clusters for n in targets(c, "google_compute_network")}
        nets |= {
            n
            for c in clusters
            for sn in targets(c, "google_compute_subnetwork")
            for n in targets(sn, "google_compute_network")
        }
        tags = {_s(t) for t in _list(_block(b, "node_config").get("tags"))}
        opened = [(p, r) for net, ports, want, r in fw if net in nets and (not want or want & tags) for p in ports]
        if opened:
            exposed[pool] = opened
        private = _s(_block(b, "network_config").get("enable_private_nodes")).lower() == "true" or any(
            _s(_block(R[c].body, "private_cluster_config").get("enable_private_nodes")).lower() == "true"
            for c in clusters
        )
        if clusters and not private:
            public_ip[pool] = "nodes with external IPs (the cluster's nodes aren't private)"

    # databases: a firewall rule admitting every address
    for r in of(*DB_FIREWALLS):
        b = R[r].body
        start, end = _s(b.get("start_ip_address")), _s(b.get("end_ip_address"))
        if start == "0.0.0.0" and end == "255.255.255.255":  # noqa: S104 - an address read, not bound
            for srv in targets(r, *(t for t in COMPONENTS if COMPONENTS[t][1] == "database")):
                exposed.setdefault(srv, []).append(("every address", r))
    for sql in of("google_sql_database_instance"):
        ipc = _block(_block(R[sql].body, "settings"), "ip_configuration")
        if _s(ipc.get("ipv4_enabled")).lower() != "false" and any(
            isinstance(n, dict) and _s(n.get("value")) in ("0.0.0.0/0", "::/0")
            for n in _list(ipc.get("authorized_networks"))
        ):
            exposed.setdefault(sql, []).append(("authorized network 0.0.0.0/0", sql))

    # storage: a public container (Azure), allUsers on a bucket or dataset (GCP)
    for c in of("azurerm_storage_container"):
        if _s(R[c].body.get("container_access_type")) in ("blob", "container"):
            for acct in targets(c, "azurerm_storage_account"):
                exposed.setdefault(acct, []).append((f"public container {R[c].name}", c))
    for b in of(*(t for t in GCP_IAM if t.startswith(("google_storage", "google_bigquery")))):
        members = {_s(m) for m in _list(R[b].body.get("members")) + _list(R[b].body.get("member"))}
        if members & PUBLIC_MEMBERS:
            for t in targets(b, "google_storage_bucket", "google_bigquery_dataset"):
                exposed.setdefault(t, []).append((", ".join(sorted(members & PUBLIC_MEMBERS)), b))
    for ds in of("google_bigquery_dataset"):
        for acc in _list(R[ds].body.get("access")):
            if isinstance(acc, dict) and _s(acc.get("special_group")) in PUBLIC_MEMBERS:
                exposed.setdefault(ds, []).append((_s(acc.get("special_group")), ds))
    # serverless anyone may invoke
    for b in of(*(t for t in GCP_IAM if "run" in t or "functions" in t)):
        members = {_s(m) for m in _list(R[b].body.get("members")) + _list(R[b].body.get("member"))}
        if "allUsers" in members and "invoker" in _s(R[b].body.get("role")):
            for t in targets(b, *SERVERLESS):
                exposed.setdefault(t, []).append(("anyone may invoke it (allUsers)", b))
    return exposed, public_ip


def badges(rtype: str, body: dict) -> list[tuple[str, bool]]:
    """Settings worth knowing on an Azure or GCP component: (text, risky)."""
    out: list[tuple[str, bool]] = []
    if rtype == "azurerm_storage_account":
        if _s(body.get("allow_nested_items_to_be_public") or body.get("allow_blob_public_access")).lower() == "true":
            out.append(("public blob access allowed", True))
        rules = _block(body, "network_rules")
        if (
            _s(rules.get("default_action") or "Allow") == "Allow"
            and _s(body.get("public_network_access_enabled")) != "false"
        ):
            out.append(("reachable from any network", False))
    if rtype in WEB_APPS and _s(body.get("https_only")).lower() != "true":
        out.append(("HTTP allowed", True))
    if rtype == "azurerm_key_vault" and _s(_block(body, "network_acls").get("default_action") or "Allow") == "Allow":
        out.append(("reachable from any network", False))
    if rtype == "azurerm_kubernetes_cluster" and public_k8s(rtype, body):
        out.append(("public API server", True))
    if rtype == "google_container_cluster":
        if public_k8s(rtype, body):
            out.append(("public control plane", True))
        if _s(body.get("enable_legacy_abac")).lower() == "true":
            out.append(("legacy ABAC", True))
    if rtype == "google_compute_instance":
        sa = _block(body, "service_account")
        if sa and any("cloud-platform" in _s(x) for x in _list(sa.get("scopes"))):
            out.append(("cloud-platform scope", True))
        if sa and not sa.get("email"):
            out.append(("default service account", True))
    return out


def public_k8s(rtype: str, body: dict) -> bool:
    if rtype == "azurerm_kubernetes_cluster":
        if _s(body.get("private_cluster_enabled")).lower() == "true":
            return False
        ranges = _list(_block(body, "api_server_access_profile").get("authorized_ip_ranges"))
        ranges += _list(body.get("api_server_authorized_ip_ranges"))
        return not ranges or any(_s(x) in ("0.0.0.0/0", "*") for x in ranges)
    if rtype == "google_container_cluster":
        if _s(_block(body, "private_cluster_config").get("enable_private_endpoint")).lower() == "true":
            return False
        man = _block(body, "master_authorized_networks_config")
        cidrs = [_s(c.get("cidr_block")) for c in _list(man.get("cidr_blocks")) if isinstance(c, dict)]
        return not man or any(c == "0.0.0.0/0" for c in cidrs)
    return False


def system_identity(rtype: str, body: dict) -> str:
    """Why a workload is its own identity: an Azure system-assigned managed identity, or GCP's default compute
    service account; "" when it isn't."""
    if cloud(rtype) == "azure" and "SystemAssigned" in _s(_block(body, "identity").get("type")):
        return "its system-assigned managed identity"
    if rtype in ("google_compute_instance", "google_compute_instance_template"):
        sa = _block(body, "service_account")
        email = _s(sa.get("email")) if sa else ""
        if sa and (not email or "compute@developer" in email or "data.google_compute_default_service_account" in email):
            return "the default compute service account"
    if rtype == "google_container_node_pool":
        sa = _s(_block(body, "node_config").get("service_account"))
        if not sa or "compute@developer" in sa or "data.google_compute_default_service_account" in sa:
            return "the default compute service account"
    if rtype in SERVERLESS and "service_account" not in str(body):
        return "the default compute service account"
    return ""


def default_sa_services(rtype: str, body: dict) -> tuple[set[str], list[str]]:
    """What GCP's default compute service account reaches: it's an Editor on the project, cut down by the instance's
    access scopes (serverless has none)."""
    if rtype == "google_container_node_pool":  # the node pool's own scopes (none when node_config sets none)
        scopes = " ".join(_s(x) for x in _list(_block(body, "node_config").get("oauth_scopes")))
    elif rtype not in ("google_compute_instance", "google_compute_instance_template"):
        return {"*"}, ["roles/editor (default compute service account)"]
    else:
        scopes = " ".join(_s(x) for x in _list(_block(body, "service_account").get("scopes")))
    if "cloud-platform" in scopes:
        return {"*"}, ["roles/editor (default compute service account, cloud-platform scope)"]
    services = set()
    if re.search(r"storage|devstorage", scopes):
        services.add("gcs")
    if "sqlservice" in scopes:
        services.add("cloudsql")
    if "bigquery" in scopes:
        services.add("bigquery")
    return services, [f"roles/editor, limited by scopes: {scopes or 'none'}"]
