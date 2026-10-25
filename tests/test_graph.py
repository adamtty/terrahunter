"""Stage 3a, the connection graph: references are resolved through variables, locals and module outputs, across
module boundaries, and holes show up as unknown nodes."""

import json

import pytest

from terrahunter import cli, graph


def write(base, files: dict[str, str]):
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return base


def edges(g) -> set[tuple[str, str, str]]:
    return {(e.source, e.target, e.attr) for e in g.edges}


def test_references_in_one_scope_with_the_attribute_they_come_from(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'resource "aws_subnet" "a" {}\nresource "aws_security_group" "web" {}\n'
            'resource "aws_instance" "web" {\n  subnet_id = aws_subnet.a.id\n'
            "  vpc_security_group_ids = [aws_security_group.web.id]\n"
            '  user_data = "mentions aws_subnet.a in plain text"\n'
            '  tags = { Name = "web-${aws_subnet.a.id}" }\n}\n'
        },
    )
    g = graph.build(tmp_path, ".")
    assert edges(g) == {
        ("aws_instance.web", "aws_subnet.a", "subnet_id"),
        ("aws_instance.web", "aws_security_group.web", "vpc_security_group_ids"),
        ("aws_instance.web", "aws_subnet.a", "tags.Name"),  # inside a template: a reference
    }  # user_data: a quoted string with no ${ } is text, never a reference
    web = g.resources["aws_instance.web"]
    assert (web.file, web.line, web.module) == ("main.tf", 3, "")


def test_module_inputs_and_outputs_wire_across_the_boundary(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'resource "aws_vpc" "main" {}\n'
            'module "net" {\n  source = "./net"\n  vpc_id = aws_vpc.main.id\n}\n'
            'resource "aws_instance" "web" {\n  subnet_id = module.net.subnet_id\n}\n',
            "net/main.tf": 'variable "vpc_id" {}\n'
            'resource "aws_subnet" "s" {\n  vpc_id = var.vpc_id\n}\n'
            'output "subnet_id" {\n  value = aws_subnet.s.id\n}\n',
        },
    )
    g = graph.build(tmp_path, ".")
    assert ("module.net.aws_subnet.s", "aws_vpc.main", "vpc_id") in edges(g)  # var → the caller's argument
    assert ("aws_instance.web", "module.net.aws_subnet.s", "subnet_id") in edges(g)  # output → the child's resource
    assert g.resources["module.net.aws_subnet.s"].file == "net/main.tf"
    assert g.modules == ["(root)", "module.net"]


def test_locals_chain_and_cycles_terminate(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'resource "aws_kms_key" "k" {}\n'
            "locals {\n  key = aws_kms_key.k.arn\n  alias = local.key\n  a = local.b\n  b = local.a\n}\n"
            'resource "aws_s3_bucket" "b" {\n  kms = local.alias\n  loop = local.a\n}\n'
        },
    )
    assert edges(graph.build(tmp_path, ".")) == {("aws_s3_bucket.b", "aws_kms_key.k", "kms")}


def test_nested_modules_pass_values_down_two_levels(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'resource "aws_iam_role" "r" {}\nmodule "app" {\n  source = "./app"\n  role = aws_iam_role.r.arn\n}\n',
            "app/main.tf": 'variable "role" {}\nmodule "fn" {\n  source = "./fn"\n  role = var.role\n}\n',
            "app/fn/main.tf": 'variable "role" {}\nresource "aws_lambda_function" "f" {\n  role = var.role\n}\n',
        },
    )
    assert ("module.app.module.fn.aws_lambda_function.f", "aws_iam_role.r", "role") in edges(graph.build(tmp_path, "."))


def test_unavailable_modules_become_unknown_nodes(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'
            'module "gone" {\n  source = "./gone"\n}\n'
            'module "picked" {\n  source = var.src\n}\n'
            'resource "aws_instance" "web" {\n  subnet_id = module.vpc.private_subnets[0]\n}\n'
        },
    )
    g = graph.build(tmp_path, ".")
    assert {a: u.status for a, u in g.unknown.items()} == {
        "module.vpc": "download",
        "module.gone": "missing",
        "module.picked": "unresolved",
    }
    assert ("aws_instance.web", "module.vpc", "subnet_id") in edges(g)  # the edge goes to the hole


def test_meta_arguments_are_not_connections_and_dynamic_blocks_are(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'resource "aws_vpc" "v" {}\nresource "aws_security_group" "src" {}\n'
            'resource "aws_security_group" "sg" {\n  count = length(aws_vpc.v.id)\n'
            "  depends_on = [aws_vpc.v]\n"
            '  dynamic "ingress" {\n    for_each = [1]\n    content {\n'
            "      security_groups = [aws_security_group.src.id]\n    }\n  }\n}\n"
        },
    )
    assert edges(graph.build(tmp_path, ".")) == {
        ("aws_security_group.sg", "aws_security_group.src", "ingress.security_groups")
    }


def test_data_sources_and_json_configuration(tmp_path):
    write(
        tmp_path,
        {
            "main.tf.json": '{"data": {"aws_ami": {"al": {}}}, "resource": {"aws_instance": {"web": '
            '{"ami": "${data.aws_ami.al.id}"}}}}'
        },
    )
    g = graph.build(tmp_path, ".")
    assert g.resources["data.aws_ami.al"].mode == "data"
    assert edges(g) == {("aws_instance.web", "data.aws_ami.al", "ami")}


def test_another_repository_with_with(tmp_path):
    repo = write(
        tmp_path / "platform",
        {
            "main.tf": 'module "dns" {\n  source = "../shared/dns"\n}\nresource "aws_x" "y" {\n  zone = module.dns.zone\n}\n'
        },
    )
    shared = write(
        tmp_path / "shared",
        {"dns/main.tf": 'resource "aws_route53_zone" "z" {}\noutput "zone" { value = aws_route53_zone.z.id }\n'},
    )
    assert "module.dns" in graph.build(repo, ".").unknown  # outside the folder: a hole
    g = graph.build(repo, ".", [shared])
    assert ("aws_x.y", "module.dns.aws_route53_zone.z", "zone") in edges(g)
    assert g.resources["module.dns.aws_route53_zone.z"].file == "shared:dns/main.tf"


def test_cli_writes_the_graph_json(tmp_path, capsys):
    write(
        tmp_path,
        {
            "main.tf": 'provider "aws" {}\nresource "aws_vpc" "v" {}\nresource "aws_subnet" "s" {\n  vpc_id = aws_vpc.v.id\n}\n'
        },
    )
    out = tmp_path / "graph.json"
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path), "--graph-json", str(out)])
    assert e.value.code == cli.EXIT_OK
    data = json.loads(out.read_text())
    assert data["graphs"][0]["edges"] == [{"source": "aws_subnet.s", "target": "aws_vpc.v", "attr": "vpc_id"}]
    assert "body" not in data["graphs"][0]["resources"][0]
    assert "2 resources, 1 connection" in capsys.readouterr().out


def test_graph_json_refuses_a_planted_symlink(tmp_path):
    write(tmp_path, {"main.tf": 'provider "aws" {}\n'})
    target = tmp_path / "victim.txt"
    target.write_text("keep me")
    (tmp_path / "graph.json").symlink_to(target)
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path), "--graph-json", str(tmp_path / "graph.json")])
    assert e.value.code == cli.EXIT_ERROR and target.read_text() == "keep me"


def test_a_heredoc_closed_with_trailing_spaces(tmp_path):
    # Terraform accepts `POLICY ` as the closing marker; the parser alone rejects the whole file
    write(
        tmp_path,
        {
            "main.tf": 'resource "aws_sqs_queue" "q" {}\nresource "aws_sqs_queue_policy" "p" {\n'
            '  queue_url = aws_sqs_queue.q.id\n  policy = <<POLICY\n{"Statement": []}\nPOLICY   \n}\n'
        },
    )
    g = graph.build(tmp_path, ".")
    assert not g.notes and ("aws_sqs_queue_policy.p", "aws_sqs_queue.q", "queue_url") in edges(g)
    assert g.resources["aws_sqs_queue_policy.p"].line == 2


def test_a_heredoc_marker_with_spaces_does_not_swallow_what_follows(tmp_path):
    # with a later heredoc closed by the same marker, the parser reads `EOF ` as content up to that one and drops
    # every block in between without an error
    run = 'resource "null_resource" "{n}" {{\n  provisioner "local-exec" {{\n    command = <<EOF\necho {n}\nEOF{sp}\n  }}\n}}\n'
    text = run.format(n="a", sp="  ") + 'resource "aws_instance" "vm" {}\n' + run.format(n="b", sp="")
    write(tmp_path, {"main.tf": text})
    g = graph.build(tmp_path, ".")
    assert {"null_resource.a", "aws_instance.vm", "null_resource.b"} <= set(g.resources)


def test_file_reads_a_policy_inside_the_folder_only(tmp_path):
    root = tmp_path / "infra"
    (root / "policies").mkdir(parents=True)
    (root / "policies" / "p.json").write_text('{"Statement": []}')
    (tmp_path / "secret.json").write_text('{"leak": true}')
    write(
        root,
        {
            "main.tf": 'resource "aws_iam_policy" "in" {\n  policy = file("${path.module}/policies/p.json")\n}\n'
            'resource "aws_iam_policy" "out" {\n  policy = file("../secret.json")\n}\n'
        },
    )
    g = graph.build(root, ".")
    assert '"Statement"' in g.resources["aws_iam_policy.in"].body["policy"]
    assert "leak" not in str(g.resources["aws_iam_policy.out"].body["policy"])  # outside the folder: not read


def test_a_shared_file_linked_into_a_root_is_read_and_a_link_out_of_the_folder_isn_t(tmp_path):
    repo = tmp_path / "repo"
    (repo / "variables").mkdir(parents=True)
    (repo / "variables" / "common.tf").write_text('variable "env" {\n  default = "prod"\n}\n')
    root = repo / "deploy" / "app"
    root.mkdir(parents=True)
    (root / "common.tf").symlink_to(repo / "variables" / "common.tf")  # shared across roots, as real estates do
    outside = tmp_path / "secret.tf"
    outside.write_text('resource "aws_s3_bucket" "planted" {}\n')
    (root / "planted.tf").symlink_to(outside)  # leaves the folder: never read
    (root / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "data-${var.env}"\n}\n')
    g = graph.build(repo, "deploy/app")
    assert g.resources["aws_s3_bucket.b"].body["bucket"] == '"data-prod"'  # the linked default was read
    assert "aws_s3_bucket.planted" not in g.resources
    assert any("planted.tf" in n and "symlink" in n for n in g.notes)
