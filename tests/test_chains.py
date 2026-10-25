"""Stage 5, attack paths: from the internet to the edge and inwards, each hop with what makes it possible, ending at
the data an identity's policies reach."""

import json

import pytest

from terrahunter import arch, chains, cli, diagram, graph

NET = (
    'provider "aws" {}\nresource "aws_vpc" "v" {}\nresource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.v.id\n}\n'
    'resource "aws_subnet" "pub" {\n  vpc_id = aws_vpc.v.id\n  map_public_ip_on_launch = true\n}\n'
    'resource "aws_subnet" "priv" {\n  vpc_id = aws_vpc.v.id\n}\n'
)
ROLE = (
    'resource "aws_iam_role" "app" {}\nresource "aws_iam_instance_profile" "app" {\n  role = aws_iam_role.app.name\n}\n'
)
BUCKETS = 'resource "aws_s3_bucket" "logs" {}\nresource "aws_s3_bucket" "customer_exports" {}\n'


def sg(name: str, *ports: int) -> str:
    rules = "".join(
        f'  ingress {{\n    from_port = {p}\n    to_port = {p}\n    cidr_blocks = ["0.0.0.0/0"]\n  }}\n' for p in ports
    )
    return f'resource "aws_security_group" "{name}" {{\n  vpc_id = aws_vpc.v.id\n{rules}}}\n'


def instance(name: str, subnet: str, group: str, extra: str = "") -> str:
    return (
        f'resource "aws_instance" "{name}" {{\n  subnet_id = aws_subnet.{subnet}.id\n'
        f"  vpc_security_group_ids = [aws_security_group.{group}.id]\n{extra}}}\n"
    )


def paths(tmp_path, text: str) -> chains.Result:
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    return chains.build(g, arch.build(g))


WILDCARD_S3 = (
    'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.app.id\n  policy = <<EOF\n'
    '{"Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]}\nEOF\n}\n'
)


def test_web_server_with_imdsv1_to_every_bucket(tmp_path):
    r = paths(
        tmp_path,
        NET
        + ROLE
        + BUCKETS
        + WILDCARD_S3
        + sg("web", 80)
        + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n"),
    )
    (c,) = r.chains
    assert (c.severity, c.confidence) == ("critical", "likely")
    assert c.steps == ["internet", "aws_instance.web", "aws_iam_role.app"]
    assert sorted(c.sinks) == ["aws_s3_bucket.customer_exports", "aws_s3_bucket.logs"]
    assert any("IMDSv1" in h and "SSRF" in h for h in c.hops)
    assert "aws_iam_role.app grants s3:* on every resource" in c.hops
    assert "aws_s3_bucket.customer_exports ⚠sensitive" in c.hops[-1]
    edges = {(e["source"], e["target"], e["label"]) for e in r.edges}
    assert ("internet", "aws_instance.web", "reaches") in edges
    assert ("aws_iam_role.app", "aws_s3_bucket.logs", "s3:*") in edges


def test_a_policy_naming_one_bucket_reaches_only_it(tmp_path):
    r = paths(
        tmp_path,
        NET + ROLE + BUCKETS + 'data "aws_iam_policy_document" "d" {\n  statement {\n    actions = ["s3:GetObject"]\n'
        "    resources = [aws_s3_bucket.logs.arn]\n  }\n}\n"
        'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.app.id\n'
        "  policy = data.aws_iam_policy_document.d.json\n}\n"
        + sg("web", 443)
        + instance(
            "web",
            "pub",
            "web",
            '  iam_instance_profile = aws_iam_instance_profile.app.name\n  metadata_options {\n    http_tokens = "required"\n  }\n',
        ),
    )
    (c,) = r.chains
    assert c.sinks == ["aws_s3_bucket.logs"]
    assert (c.severity, c.confidence) == ("high", "possible")  # IMDSv2: the app itself has to fall first
    assert "aws_iam_role.app grants s3:GetObject on the resources it names" in c.hops


def test_through_a_load_balancer_and_once_per_workload(tmp_path):
    lb = (
        'resource "aws_lb" "front" {\n  security_groups = [aws_security_group.lb.id]\n}\n'
        'resource "aws_lb_target_group" "tg" {}\n'
        'resource "aws_lb_listener" "l" {\n  load_balancer_arn = aws_lb.front.arn\n'
        "  default_action {\n    target_group_arn = aws_lb_target_group.tg.arn\n  }\n}\n"
        'resource "aws_lb_target_group_attachment" "a" {\n  target_group_arn = aws_lb_target_group.tg.arn\n'
        "  target_id = aws_instance.app.id\n}\n"
    )
    profile = "  iam_instance_profile = aws_iam_instance_profile.app.name\n"
    r = paths(
        tmp_path,
        NET + ROLE + BUCKETS + WILDCARD_S3 + lb + sg("lb", 443) + sg("app") + instance("app", "priv", "app", profile),
    )
    (c,) = r.chains  # the private instance isn't an entry by itself: only through the load balancer
    assert c.steps == ["internet", "aws_lb.front", "aws_instance.app", "aws_iam_role.app"]
    assert "aws_lb.front routes to aws_instance.app" in c.hops
    # also reachable directly: one chain, the shortest way in, with a note
    r = paths(
        tmp_path,
        NET
        + ROLE
        + BUCKETS
        + WILDCARD_S3
        + lb
        + sg("lb", 443)
        + sg("app", 22)
        + instance("app", "pub", "app", profile),
    )
    # also reachable over SSH (possible: it needs a key), but web traffic into IMDSv1 with a role is likely: one
    # chain, the likelier way in, with the other kept as an alternative
    (c,) = r.chains
    assert c.steps == ["internet", "aws_lb.front", "aws_instance.app", "aws_iam_role.app"]
    assert c.confidence == "likely" and c.also == ["aws_instance.app"]
    assert "aws_instance.app is also reachable directly from the internet" in c.hops


def test_exposed_data_stores_are_direct(tmp_path):
    r = paths(
        tmp_path,
        NET + sg("db", 5432) + 'resource "aws_db_instance" "billing" {\n  publicly_accessible = true\n'
        "  vpc_security_group_ids = [aws_security_group.db.id]\n}\n"
        # publicly accessible, but no security group open to the internet: not exposed
        'resource "aws_db_instance" "internal" {\n  publicly_accessible = true\n}\n'
        'resource "aws_s3_bucket" "site" {\n  acl = "public-read"\n}\n'
        'resource "aws_elasticsearch_domain" "search" {\n  vpc_options {\n    subnet_ids = [aws_subnet.priv.id]\n  }\n}\n',
    )
    got = {(c.sinks[0], c.severity, c.confidence) for c in r.chains}
    assert got == {("aws_db_instance.billing", "critical", "direct"), ("aws_s3_bucket.site", "critical", "direct")}
    assert all(c.steps == ["internet"] for c in r.chains)
    assert ("internet", "aws_db_instance.billing") in {(e["source"], e["target"]) for e in r.edges}


def test_a_long_lived_key_is_a_badge_not_a_path(tmp_path):
    (tmp_path / "main.tf").write_text(
        BUCKETS
        + 'resource "aws_iam_user" "ci" {}\nresource "aws_iam_access_key" "k" {\n  user = aws_iam_user.ci.name\n}\n'
        'resource "aws_iam_user_policy_attachment" "a" {\n  user = aws_iam_user.ci.name\n'
        '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}\n'
    )
    g = graph.build(tmp_path, ".")
    m = arch.build(g)
    user = next(c for c in m.components if c.id == "aws_iam_user.ci")
    assert any(b.text == "long-lived access key" and b.risk for b in user.badges)
    assert chains.build(g, m).chains == []  # a key only in Terraform state isn't reachable


def test_a_function_url_with_no_auth(tmp_path):
    r = paths(
        tmp_path,
        BUCKETS + 'resource "aws_iam_role" "fn" {}\n'
        'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.fn.id\n  policy = jsonencode({\n'
        '    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]\n  })\n}\n'
        'resource "aws_lambda_function" "f" {\n  function_name = "f"\n  role = aws_iam_role.fn.arn\n}\n'
        'resource "aws_lambda_function_url" "u" {\n  function_name = aws_lambda_function.f.function_name\n'
        '  authorization_type = "NONE"\n}\n',
    )
    (c,) = r.chains
    assert c.steps == ["internet", "aws_lambda_function_url.u", "aws_lambda_function.f", "aws_iam_role.fn"]
    assert len(c.sinks) == 2 and c.severity == "critical"  # Action "*": everything


@pytest.mark.parametrize(
    "text",
    [
        NET + ROLE + BUCKETS + WILDCARD_S3 + sg("web", 80) + instance("web", "priv", "web"),  # no public IP
        NET + sg("web") + instance("web", "pub", "web"),  # nothing open to the internet
        NET + 'resource "aws_lb" "in" {\n  internal = true\n}\n',  # an internal load balancer
    ],
)
def test_nothing_reaches_in(tmp_path, text):
    assert paths(tmp_path, text).chains == []


def test_the_cli_and_the_diagram(tmp_path, capsys):
    (tmp_path / "main.tf").write_text(
        NET
        + ROLE
        + BUCKETS
        + WILDCARD_S3
        + sg("web", 80)
        + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n")
    )
    out, page = tmp_path / "g.json", tmp_path / "d.html"
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path), "--no-scan", "--graph-json", str(out), "--diagram", str(page)])
    text = capsys.readouterr().out
    assert "Attack paths: 1" in text and "internet → web → app → 2 data stores" in text
    assert json.loads(out.read_text())["graphs"][0]["attack_paths"][0]["confidence"] == "likely"
    html = page.read_text()
    blob = json.loads(html.split('type="application/json">', 1)[1].split("</script>", 1)[0])
    assert blob["internet"] and blob["walked"] and len([c for c in blob["chains"] if not c.get("leak")]) == 1
    # and what the role's credentials would give, listed after the paths
    assert [c["steps"] for c in blob["chains"] if c.get("leak")] == [["attacker-principal", "aws_iam_role.app"]]
    assert "If these credentials leak: 1 identity" in text
    assert {"internet", "aws_iam_role.app"} <= {e["source"] for e in blob["edges"]}


def test_the_diagram_without_paths_says_so(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    g = graph.build(tmp_path, ".")
    page = diagram.render(arch.build(g), "t")
    assert '"walked": false' in page and '"internet": false' in page


def test_what_is_stored_in_a_store_comes_with_it(tmp_path):
    r = paths(
        tmp_path,
        NET
        + ROLE
        + BUCKETS
        + WILDCARD_S3
        + 'resource "aws_s3_object" "report" {\n  bucket = aws_s3_bucket.customer_exports.id\n  key = "r.csv"\n}\n'
        + sg("web", 80)
        + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n"),
    )
    (c,) = r.chains
    assert "aws_s3_bucket.customer_exports" in c.sinks and c.within == ["aws_s3_object.report"]


@pytest.mark.parametrize(
    ("own", "sinks"),
    [
        ('  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonS3FullAccess"]\n', ["aws_s3_bucket.logs"]),
        (
            (
                '  inline_policy {\n    name = "i"\n    policy = jsonencode({Statement = [{Effect = "Allow", '
                'Action = "dynamodb:*", Resource = "*"}]})\n  }\n'
            ),
            ["aws_dynamodb_table.orders"],
        ),
        ("", []),  # the trust policy alone grants nothing
    ],
)
def test_a_role_s_own_policies(tmp_path, own, sinks):
    role = (
        'resource "aws_iam_role" "app" {\n  assume_role_policy = jsonencode({Statement = [{Effect = "Allow", '
        'Principal = {Service = "ec2.amazonaws.com"}, Action = "sts:AssumeRole"}]})\n' + own + "}\n"
        'resource "aws_iam_instance_profile" "app" {\n  role = aws_iam_role.app.name\n}\n'
    )
    r = paths(
        tmp_path,
        NET
        + role
        + 'resource "aws_s3_bucket" "logs" {}\nresource "aws_dynamodb_table" "orders" {}\n'
        + sg("web", 80)
        + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n"),
    )
    assert sorted(s for c in r.chains for s in c.sinks) == sinks


@pytest.mark.parametrize(
    ("login", "found"),
    [("", False), ('  key_name = "ops"\n', True), ('  user_data = "echo root:pw | chpasswd"\n', True)],
)
def test_ssh_open_is_a_way_in_only_with_a_login(tmp_path, login, found):
    # SSH open to the world, but with no key pair and no password nobody can log in
    r = paths(tmp_path, NET + sg("ssh", 22) + instance("box", "pub", "ssh", login))
    assert bool(r.chains) is found


def test_an_internet_path_carries_on_with_the_role_s_credentials(tmp_path):
    # the instance's role can assume an admin role: the path reaches what that role reaches, and records it
    admin = (
        'resource "aws_iam_role" "admin" {\n  assume_role_policy = jsonencode({Statement = [{Effect = "Allow", '
        'Action = "sts:AssumeRole", Principal = {AWS = aws_iam_role.app.arn}}]})\n'
        '  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]\n}\n'
        'resource "aws_dynamodb_table" "orders" {}\n'
    )
    r = paths(
        tmp_path,
        NET
        + ROLE
        + admin
        + sg("web", 80)
        + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n"),
    )
    (c,) = r.chains
    assert "aws_iam_role.admin" in c.controls and "aws_dynamodb_table.orders" in c.sinks
    assert any("with aws_iam_role.app's credentials" in h and "privesc-sts-001" in h for h in c.hops)


def test_a_private_key_in_a_public_bucket_logs_in_to_the_machine_that_trusts_it(tmp_path):
    (tmp_path / "files" / "keys").mkdir(parents=True)
    (tmp_path / "files" / "keys" / "justin.pem").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    (tmp_path / "files" / "index.html").write_text("<p>hi</p>")
    r = paths(
        tmp_path,
        NET + ROLE + sg("ssh", 22) + 'resource "aws_s3_bucket" "site" {\n  acl = "public-read"\n}\n'
        'resource "aws_s3_object" "files" {\n  for_each = fileset("${path.module}/files", "**")\n'
        '  bucket = aws_s3_bucket.site.id\n  key = each.value\n  source = "${path.module}/files/${each.value}"\n}\n'
        + instance(
            "dev",
            "pub",
            "ssh",
            '  user_data = "curl -o /home/justin/.ssh/authorized_keys https://site/keys/justin.pub"\n'
            "  iam_instance_profile = aws_iam_instance_profile.app.name\n",
        )
        + instance("other", "pub", "ssh", '  key_name = "ops"\n'),
    )
    (ch,) = [c for c in r.chains if c.kind == "internet → public store → SSH key → VM"]
    assert ch.steps == ["internet", "aws_s3_bucket.site", "aws_instance.dev", "aws_iam_role.app"]
    assert ch.confidence == "likely" and "justin.pem" in ch.hops[-3]


def test_an_older_provider_names_the_container_a_blob_is_in(tmp_path):
    # azurerm 3 and 4 took names where 5 takes the container's id
    (tmp_path / "main.tf").write_text(
        'resource "azurerm_storage_container" "c" {}\n'
        'resource "azurerm_storage_blob" "b" {\n  storage_container_name = azurerm_storage_container.c.name\n}\n'
    )
    g = graph.build(tmp_path, ".")
    (e,) = [e for e in g.edges if e.source == "azurerm_storage_blob.b"]
    assert chains._stores_in(e, g.resources)


FN = (
    'resource "aws_iam_role" "fn" {}\nresource "aws_lambda_function" "consumer" {\n  function_name = "c"\n'
    "  role = aws_iam_role.fn.arn\n}\n"
    'resource "aws_ssm_parameter" "flag" {\n  name = "/flag"\n  type = "SecureString"\n  value = "x"\n}\n'
    'resource "aws_ssm_parameter" "other" {\n  name = "/other"\n  type = "SecureString"\n  value = "y"\n}\n'
    'resource "aws_iam_role_policy" "fn" {\n  role = aws_iam_role.fn.id\n  policy = jsonencode({Statement = [\n'
    '    {Effect = "Allow", Action = "ssm:GetParameter", Resource = aws_ssm_parameter.flag.arn},\n'
    '    {Effect = "Allow", Action = "logs:*", Resource = "*"}]})\n}\n'
)


def test_a_public_queue_feeds_the_function_it_triggers(tmp_path):
    r = paths(
        tmp_path,
        FN + 'resource "aws_sqs_queue" "bus" {}\n'
        'resource "aws_sqs_queue_policy" "p" {\n  queue_url = aws_sqs_queue.bus.id\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Principal = "*", Action = "sqs:SendMessage", '
        "Resource = aws_sqs_queue.bus.arn}]})\n}\n"
        'resource "aws_lambda_event_source_mapping" "m" {\n  event_source_arn = aws_sqs_queue.bus.arn\n'
        "  function_name = aws_lambda_function.consumer.arn\n}\n",
    )
    (ch,) = [c for c in r.chains if "aws_sqs_queue.bus" in c.steps or "aws_sqs_queue.bus" in c.sinks]
    assert ch.steps == ["internet", "aws_sqs_queue.bus", "aws_lambda_function.consumer", "aws_iam_role.fn"]
    # one statement's resource isn't another's: GetParameter on the flag only, though logs:* is on every resource
    assert "aws_ssm_parameter.flag" in ch.sinks and "aws_ssm_parameter.other" not in ch.sinks


def test_a_machine_holding_an_access_key_gives_its_user(tmp_path):
    r = paths(
        tmp_path,
        NET + ROLE + sg("open", 22) + 'resource "aws_iam_user" "admin" {}\n'
        'resource "aws_iam_access_key" "k" {\n  user = aws_iam_user.admin.name\n}\n'
        'resource "aws_iam_user_policy" "a" {\n  user = aws_iam_user.admin.name\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = "s3:*", Resource = "*"}]})\n}\n'
        'resource "aws_s3_bucket" "vault" {}\n'
        + instance(
            "box",
            "pub",
            "open",
            '  key_name = "ops"\n  associate_public_ip_address = true\n'
            "  iam_instance_profile = aws_iam_instance_profile.app.name\n"
            '  provisioner "file" {\n    content = "${aws_iam_access_key.k.secret}"\n    destination = "/tmp/k"\n  }\n',
        ),
    )
    (ch,) = [c for c in r.chains if "aws_instance.box" in c.steps]  # one path: the role, with the key's user
    assert "aws_iam_user.admin" in ch.steps + ch.controls and "aws_s3_bucket.vault" in ch.sinks
