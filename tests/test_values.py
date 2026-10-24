"""Values known before apply: variables (defaults, tfvars, --var-file, --var), module arguments and locals, evaluated
into resource bodies; blocks with count = 0 or an empty for_each leave the graph."""

import json

import pytest

from terrahunter import arch, chains, cli, graph, values


def ev(text: str, env: dict | None = None):
    def resolve(kind, name):
        try:
            return (env or {})[f"{kind}.{name}"]
        except KeyError:
            raise values.Unknown(name) from None

    return values.Evaluator(resolve).expr(text)


@pytest.mark.parametrize(
    ("text", "env", "out"),
    [
        ('var.public ? "0.0.0.0/0" : "10.0.0.0/8"', {"var.public": True}, "0.0.0.0/0"),
        ("var.n > 1 && !var.off", {"var.n": 2, "var.off": False}, True),
        ('"web-${var.env}-${local.n + 1}"', {"var.env": "prod", "local.n": 1}, "web-prod-2"),
        ("length(concat(var.a, [1]))", {"var.a": [1, 2]}, 3),
        ('lookup(var.m, "k", "d")', {"var.m": {"x": 1}}, "d"),
        ("var.cfg.ports[1]", {"var.cfg": {"ports": [22, 443]}}, 443),
        ('format("%s/%d", "10.0.0.0", 16)', {}, "10.0.0.0/16"),
        ("{ a = 1, b = [true] }", {}, {"a": 1, "b": [True]}),
    ],
)
def test_expressions(text, env, out):
    assert ev(text, env) == out


@pytest.mark.parametrize(
    "text", ["aws_vpc.main.id", "var.unset", "[for s in var.a : s]", "data.x.y.z", "var.a[*].id", "timestamp()"]
)
def test_what_only_apply_knows_is_unknown(text):
    with pytest.raises(values.Unknown):
        ev(text, {"var.a": [1]})


def write(base, files):
    for rel, text in files.items():
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text(text)
    return base


NET = 'resource "aws_vpc" "v" {}\n'
SG = (
    'variable "allowed" {\n  default = "10.0.0.0/8"\n}\n'
    'resource "aws_security_group" "web" {\n  vpc_id = aws_vpc.v.id\n'
    "  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = [var.allowed]\n  }\n}\n"
)


def cidr(g):
    return g.resources["aws_security_group.web"].body["ingress"][0]["cidr_blocks"]


def test_precedence_default_tfvars_auto_varfile_var(tmp_path):
    write(tmp_path, {"main.tf": NET + SG})
    assert cidr(graph.build(tmp_path, ".")) == ['"10.0.0.0/8"']
    write(tmp_path, {"terraform.tfvars": 'allowed = "1.1.1.1/32"\n'})
    assert cidr(graph.build(tmp_path, ".")) == ['"1.1.1.1/32"']
    write(tmp_path, {"b.auto.tfvars.json": json.dumps({"allowed": "2.2.2.2/32"})})
    assert cidr(graph.build(tmp_path, ".")) == ['"2.2.2.2/32"']
    extra = write(tmp_path / "x", {"prod.tfvars": 'allowed = "3.3.3.3/32"\n'}) / "prod.tfvars"
    assert cidr(graph.build(tmp_path, ".", var_files=[extra])) == ['"3.3.3.3/32"']
    assert cidr(graph.build(tmp_path, ".", variables={"allowed": '"0.0.0.0/0"'}, var_files=[extra])) == ['"0.0.0.0/0"']


def test_references_stay_and_unknown_values_stay_expressions(tmp_path):
    write(tmp_path, {"main.tf": NET + SG.replace('default = "10.0.0.0/8"', "")})
    g = graph.build(tmp_path, ".")
    assert cidr(g) == ["${var.allowed}"]  # no value: left as written
    assert g.resources["aws_security_group.web"].body["vpc_id"] == "${aws_vpc.v.id}"
    assert ("aws_security_group.web", "aws_vpc.v", "vpc_id") in {(e.source, e.target, e.attr) for e in g.edges}


def test_module_arguments_and_locals(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": NET
            + 'variable "env" {\n  default = "prod"\n}\n'
            + 'module "web" {\n  source = "./web"\n  vpc = aws_vpc.v.id\n  open = var.env == "prod"\n}\n',
            "web/main.tf": 'variable "vpc" {}\nvariable "open" {}\nvariable "port" {\n  default = 443\n}\n'
            'locals {\n  cidr = var.open ? "0.0.0.0/0" : "10.0.0.0/8"\n}\n'
            'resource "aws_security_group" "sg" {\n  vpc_id = var.vpc\n  name = "sg-${var.port}"\n'
            "  ingress {\n    from_port = var.port\n    to_port = var.port\n    cidr_blocks = [local.cidr]\n  }\n}\n",
        },
    )
    b = graph.build(tmp_path, ".").resources["module.web.aws_security_group.sg"].body
    assert (b["ingress"][0]["cidr_blocks"], b["ingress"][0]["from_port"], b["name"]) == (
        ['"0.0.0.0/0"'],
        443,
        '"sg-443"',
    )
    assert b["vpc_id"] == "${var.vpc}"  # passed a resource attribute: unknown


def test_count_and_for_each_prune_blocks_and_modules(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": NET + 'variable "enabled" {\n  default = false\n}\nvariable "names" {\n  default = []\n}\n'
            'resource "aws_s3_bucket" "off" {\n  count = var.enabled ? 1 : 0\n}\n'
            'resource "aws_s3_bucket" "none" {\n  for_each = toset(var.names)\n}\n'
            'resource "aws_s3_bucket" "on" {\n  count = 2\n}\n'
            'module "extra" {\n  source = "./extra"\n  count = var.enabled ? 1 : 0\n}\n'
            'module "remote" {\n  source = "terraform-aws-modules/vpc/aws"\n  count = 0\n}\n',
            "extra/main.tf": 'resource "aws_s3_bucket" "inside" {}\n',
        },
    )
    g = graph.build(tmp_path, ".")
    assert sorted(g.resources) == ["aws_s3_bucket.on", "aws_vpc.v"]
    assert g.modules == ["(root)"] and not g.unknown and not g.notes
    assert "not deployed" in g.info[0] and "module.extra" in g.info[0]
    g = graph.build(tmp_path, ".", variables={"enabled": True})
    assert "module.extra.aws_s3_bucket.inside" in g.resources and "aws_s3_bucket.off" in g.resources


def test_a_variable_cidr_makes_the_path(tmp_path, capsys):
    write(
        tmp_path,
        {
            "main.tf": NET + 'resource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.v.id\n}\n'
            'resource "aws_subnet" "pub" {\n  vpc_id = aws_vpc.v.id\n  map_public_ip_on_launch = true\n}\n'
            + SG.replace('default = "10.0.0.0/8"', "")
            + 'resource "aws_instance" "i" {\n  subnet_id = aws_subnet.pub.id\n'
            "  vpc_security_group_ids = [aws_security_group.web.id]\n}\n"
        },
    )
    g = graph.build(tmp_path, ".")
    assert chains.build(g, arch.build(g)).chains == []  # open to whom? unknown
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path), "--no-scan", "--no-diagram", "--var", 'allowed="0.0.0.0/0"'])
    assert "Attack paths: 1" in capsys.readouterr().out


def test_cli_var_errors(tmp_path, capsys):
    write(tmp_path, {"main.tf": NET})
    for bad in (["--var", "noequals"], ["--var-file", str(tmp_path / "missing.tfvars")]):
        with pytest.raises(SystemExit) as e:
            cli.main([str(tmp_path), "--no-scan", "--no-diagram", *bad])
        assert e.value.code == cli.EXIT_ERROR
    assert cli.parse_vars(["region=eu-west-1", "ports=[22, 443]"]) == {"region": '"eu-west-1"', "ports": [22, 443]}
