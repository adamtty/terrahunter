"""Azure and Google Cloud: the same map (subscription / project, networks, subnets, services, identities), the same
exposure (network security groups, firewall rules, database firewalls, public containers and buckets), and the same
attack paths through what a workload runs as to what its role assignments or IAM bindings reach."""

import pytest

from terrahunter import arch, chains, graph

AZ_NET = (
    'resource "azurerm_resource_group" "rg" {}\nresource "azurerm_resource_group" "other" {}\n'
    'resource "azurerm_virtual_network" "vnet" {\n  resource_group_name = azurerm_resource_group.rg.name\n'
    '  address_space = ["10.0.0.0/16"]\n}\n'
    'resource "azurerm_subnet" "app" {\n  virtual_network_name = azurerm_virtual_network.vnet.name\n'
    '  address_prefixes = ["10.0.1.0/24"]\n}\n'
    'resource "azurerm_public_ip" "pip" {}\n'
    'resource "azurerm_network_interface" "nic" {\n  ip_configuration {\n    subnet_id = azurerm_subnet.app.id\n'
    "    public_ip_address_id = azurerm_public_ip.pip.id\n  }\n}\n"
    'resource "azurerm_storage_account" "logs" {\n  resource_group_name = azurerm_resource_group.rg.name\n}\n'
    'resource "azurerm_storage_account" "elsewhere" {\n  resource_group_name = azurerm_resource_group.other.name\n}\n'
)
NSG_SSH = (
    'resource "azurerm_network_security_group" "nsg" {\n  security_rule {\n    direction = "Inbound"\n'
    '    access = "Allow"\n    source_address_prefix = "*"\n    destination_port_range = "22"\n  }\n}\n'
    'resource "azurerm_network_interface_security_group_association" "a" {\n'
    "  network_interface_id = azurerm_network_interface.nic.id\n"
    "  network_security_group_id = azurerm_network_security_group.nsg.id\n}\n"
)
VM = (
    'resource "azurerm_linux_virtual_machine" "vm" {\n  network_interface_ids = [azurerm_network_interface.nic.id]\n'
    '  identity {\n    type = "SystemAssigned"\n  }\n}\n'
)


def build(tmp_path, text: str):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    m = arch.build(g)
    return g, m, chains.build(g, m)


def comp(m, addr):
    return next(c for c in m.components if c.id == addr)


def test_azure_vm_through_its_nic_to_a_scoped_storage_role(tmp_path):
    _, m, r = build(
        tmp_path,
        AZ_NET
        + NSG_SSH
        + VM
        + 'resource "azurerm_role_assignment" "ra" {\n  principal_id = azurerm_linux_virtual_machine.vm.identity[0].principal_id\n'
        '  role_definition_name = "Storage Blob Data Reader"\n  scope = azurerm_storage_account.logs.id\n}\n',
    )
    vm = comp(m, "azurerm_linux_virtual_machine.vm")
    assert vm.parent == "azurerm_subnet.app"  # placed through its NIC
    labels = {c.id: c.label for c in m.containers}
    assert labels["azurerm_virtual_network.vnet"] == "VNet vnet · 10.0.0.0/16"
    assert labels["azurerm_subnet.app"] == "Subnet app · 10.0.1.0/24" and labels["azure"] == "Azure subscription"
    assert {b.text for b in vm.badges} >= {"open to internet: 22", "public IP"}
    (c,) = r.chains
    assert c.steps == ["internet", "azurerm_linux_virtual_machine.vm"]  # its own identity: no extra step
    assert c.sinks == ["azurerm_storage_account.logs"]
    assert any("system-assigned managed identity" in h for h in c.hops)
    assert "network security group" in c.entry
    (close,) = [f for f in r.fixes if f.id.startswith("close")]
    assert close.action == "Close 22 to the internet in network security group nsg"


def test_azure_subnet_nsg_with_a_separate_rule_and_a_resource_group_scope(tmp_path):
    _, _, r = build(
        tmp_path,
        AZ_NET + 'resource "azurerm_network_security_group" "nsg" {}\n'
        'resource "azurerm_network_security_rule" "rdp" {\n  network_security_group_name = azurerm_network_security_group.nsg.name\n'
        '  direction = "Inbound"\n  access = "Allow"\n  source_address_prefix = "Internet"\n'
        '  destination_port_range = "3389"\n}\n'
        'resource "azurerm_subnet_network_security_group_association" "a" {\n  subnet_id = azurerm_subnet.app.id\n'
        "  network_security_group_id = azurerm_network_security_group.nsg.id\n}\n"
        'resource "azurerm_user_assigned_identity" "id" {}\n'
        'resource "azurerm_windows_virtual_machine" "vm" {\n  network_interface_ids = [azurerm_network_interface.nic.id]\n'
        '  identity {\n    type = "UserAssigned"\n    identity_ids = [azurerm_user_assigned_identity.id.id]\n  }\n}\n'
        'resource "azurerm_role_assignment" "ra" {\n  principal_id = azurerm_user_assigned_identity.id.principal_id\n'
        '  role_definition_name = "Contributor"\n  scope = azurerm_resource_group.rg.id\n}\n',
    )
    (c,) = r.chains
    assert c.steps == ["internet", "azurerm_windows_virtual_machine.vm", "azurerm_user_assigned_identity.id"]
    assert c.sinks == ["azurerm_storage_account.logs"]  # in the group; not the account in the other one
    assert "Contributor" in next(h for h in c.hops if "grants" in h)
    by = {f.id.split(":")[0]: f for f in r.fixes}
    assert by["close"].where[0]["address"] == "azurerm_network_security_rule.rdp"
    assert "network security group nsg" in by["close"].action
    assert by["scope"].where[0]["address"] == "azurerm_role_assignment.ra"


def test_azure_web_app_to_a_key_vault(tmp_path):
    _, _, r = build(
        tmp_path,
        'resource "azurerm_key_vault" "kv" {}\n'
        'resource "azurerm_linux_web_app" "app" {\n  https_only = false\n  identity {\n    type = "SystemAssigned"\n  }\n}\n'
        'resource "azurerm_key_vault_access_policy" "p" {\n  key_vault_id = azurerm_key_vault.kv.id\n'
        "  object_id = azurerm_linux_web_app.app.identity[0].principal_id\n}\n",
    )
    (c,) = r.chains
    assert c.entry == "app: web app on the internet, HTTP allowed"
    assert c.sinks == ["azurerm_key_vault.kv"] and c.severity == "critical"  # a key vault is sensitive


@pytest.mark.parametrize(
    ("extra", "store", "fix"),
    [
        (
            (
                'resource "azurerm_mssql_server" "db" {}\nresource "azurerm_mssql_firewall_rule" "all" {\n'
                '  server_id = azurerm_mssql_server.db.id\n  start_ip_address = "0.0.0.0"\n  end_ip_address = "255.255.255.255"\n}\n'
            ),
            "azurerm_mssql_server.db",
            "azurerm_mssql_firewall_rule.all",
        ),
        (
            (
                'resource "azurerm_storage_account" "st" {}\nresource "azurerm_storage_container" "c" {\n'
                '  storage_account_name = azurerm_storage_account.st.name\n  container_access_type = "blob"\n}\n'
            ),
            "azurerm_storage_account.st",
            "azurerm_storage_container.c",
        ),
        (
            (
                'resource "google_storage_bucket" "b" {}\nresource "google_storage_bucket_iam_member" "pub" {\n'
                '  bucket = google_storage_bucket.b.name\n  role = "roles/storage.objectViewer"\n  member = "allUsers"\n}\n'
            ),
            "google_storage_bucket.b",
            "google_storage_bucket_iam_member.pub",
        ),
        (
            (
                'resource "google_sql_database_instance" "db" {\n  settings {\n    ip_configuration {\n'
                '      ipv4_enabled = true\n      authorized_networks {\n        value = "0.0.0.0/0"\n      }\n    }\n  }\n}\n'
            ),
            "google_sql_database_instance.db",
            "google_sql_database_instance.db",
        ),
    ],
)
def test_exposed_data_stores(tmp_path, extra, store, fix):
    _, _, r = build(tmp_path, extra)
    (c,) = r.chains
    assert (c.steps, c.sinks, c.confidence) == (["internet"], [store], "direct")
    assert r.fixes[0].where[0]["address"] == fix and r.fixes[0].effect == "breaks"


def test_an_unattached_nsg_and_a_single_address_open_nothing(tmp_path):
    _, _, r = build(
        tmp_path,
        AZ_NET
        + NSG_SSH.split('resource "azurerm_network_interface_security_group_association"')[0]
        + VM
        + 'resource "azurerm_sql_server" "db" {}\nresource "azurerm_sql_firewall_rule" "one" {\n'
        '  server_name = azurerm_sql_server.db.name\n  start_ip_address = "10.0.17.62"\n  end_ip_address = "10.0.17.62"\n}\n',
    )
    assert r.chains == []


GCP_NET = (
    'resource "google_compute_network" "vpc" {}\n'
    'resource "google_compute_subnetwork" "sub" {\n  network = google_compute_network.vpc.id\n  ip_cidr_range = "10.2.0.0/16"\n}\n'
    'resource "google_compute_firewall" "ssh" {\n  network = google_compute_network.vpc.name\n'
    '  source_ranges = ["0.0.0.0/0"]\n  target_tags = ["web"]\n  allow {\n    protocol = "tcp"\n    ports = ["22"]\n  }\n}\n'
    'resource "google_storage_bucket" "assets" {}\nresource "google_storage_bucket" "customer_data" {}\n'
)


def gce(name: str, tags: str, sa: str) -> str:
    return (
        f'resource "google_compute_instance" "{name}" {{\n  tags = [{tags}]\n'
        "  network_interface {\n    subnetwork = google_compute_subnetwork.sub.id\n    access_config {}\n  }\n"
        f"{sa}}}\n"
    )


def test_gcp_firewall_by_tag_to_a_service_account_scoped_to_one_bucket(tmp_path):
    _, m, r = build(
        tmp_path,
        GCP_NET
        + 'resource "google_service_account" "app" {}\n'
        + gce("web", '"web"', "  service_account {\n    email = google_service_account.app.email\n  }\n")
        + gce("db", '"db"', "")  # not tagged web: the rule doesn't apply
        + 'resource "google_storage_bucket_iam_member" "m" {\n  bucket = google_storage_bucket.assets.name\n'
        '  role = "roles/storage.objectAdmin"\n  member = "serviceAccount:${google_service_account.app.email}"\n}\n',
    )
    web = comp(m, "google_compute_instance.web")
    assert web.parent == "google_compute_subnetwork.sub" and "open to internet: 22" in {b.text for b in web.badges}
    assert not any(b.text.startswith("open to internet") for b in comp(m, "google_compute_instance.db").badges)
    (c,) = r.chains
    assert c.steps == ["internet", "google_compute_instance.web", "google_service_account.app"]
    assert c.sinks == ["google_storage_bucket.assets"]  # the binding is on that bucket only
    assert "firewall rule ssh" in next(f.action for f in r.fixes if f.id.startswith("close"))


def test_gcp_default_service_account_with_cloud_platform_scope(tmp_path):
    _, m, r = build(
        tmp_path,
        GCP_NET + gce("web", '"web"', '  service_account {\n    scopes = ["cloud-platform"]\n  }\n'),
    )
    assert {"default service account", "cloud-platform scope"} <= {
        b.text for b in comp(m, "google_compute_instance.web").badges
    }
    (c,) = r.chains
    assert c.steps == ["internet", "google_compute_instance.web"]
    assert sorted(c.sinks) == ["google_storage_bucket.assets", "google_storage_bucket.customer_data"]
    assert c.severity == "critical"  # editor on the project, and customer data among it
    assert any("its own service account" in f.action for f in r.fixes)


def test_gcp_cloud_run_anyone_can_invoke_to_a_secret(tmp_path):
    _, _, r = build(
        tmp_path,
        'resource "google_service_account" "run" {}\nresource "google_secret_manager_secret" "db_password" {}\n'
        'resource "google_cloud_run_v2_service" "api" {\n  template {\n'
        "    service_account = google_service_account.run.email\n  }\n}\n"
        'resource "google_cloud_run_v2_service_iam_member" "pub" {\n  name = google_cloud_run_v2_service.api.name\n'
        '  role = "roles/run.invoker"\n  member = "allUsers"\n}\n'
        'resource "google_project_iam_member" "sm" {\n  role = "roles/secretmanager.secretAccessor"\n'
        '  member = "serviceAccount:${google_service_account.run.email}"\n}\n',
    )
    (c,) = r.chains
    assert c.steps == ["internet", "google_cloud_run_v2_service.api", "google_service_account.run"]
    assert c.sinks == ["google_secret_manager_secret.db_password"] and c.severity == "critical"
    assert "anyone may invoke it" in c.entry


def test_gcp_service_account_key_is_a_badge_not_a_path(tmp_path):
    _, m, r = build(
        tmp_path,
        'resource "google_service_account" "ci" {}\nresource "google_service_account_key" "k" {\n'
        "  service_account_id = google_service_account.ci.name\n}\n"
        'resource "google_storage_bucket" "b" {}\nresource "google_project_iam_member" "ed" {\n'
        '  role = "roles/editor"\n  member = "serviceAccount:${google_service_account.ci.email}"\n}\n',
    )
    assert "long-lived access key" in {b.text for b in comp(m, "google_service_account.ci").badges}
    assert r.chains == []
