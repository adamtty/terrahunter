"""Plan mode: a `terraform show -json` plan turns resource blocks into the instances that will be deployed, puts the
resolved values in place of expressions (never sensitive ones), and re-draws connections between instances.

fixtures/plan is a real plan (terraform 1.17, made offline with -refresh=false): a count = 2 subnet, a count = 0
bucket, a module called with for_each over ["a", "b"] given `aws_subnet.pub[0]`, and a security group whose CIDR comes
from `var.public ? "0.0.0.0/0" : "10.0.0.0/8"`."""

import json
import shutil
from pathlib import Path

import pytest

from terrahunter import arch, chains, cli, graph, plan

FIXTURE = Path(__file__).parent / "fixtures" / "plan"


@pytest.fixture
def estate(tmp_path):
    shutil.copytree(FIXTURE, tmp_path / "repo")
    return tmp_path / "repo"


def planned(estate):
    return plan.apply(graph.build(estate, "."), plan.load(estate / "plan.json"))


def test_instances_replace_blocks(estate):
    g = planned(estate)
    assert sorted(g.resources) == [
        "aws_subnet.pub[0]",
        "aws_subnet.pub[1]",
        "aws_vpc.v",
        'module.web["a"].aws_instance.web',
        'module.web["a"].aws_security_group.web',
        'module.web["b"].aws_instance.web',
        'module.web["b"].aws_security_group.web',
    ]
    assert any("count = 0" in n and "aws_s3_bucket.unused" in n for n in g.info) and not g.notes
    web = g.resources['module.web["a"].aws_instance.web']
    assert (web.name, web.module, web.file) == ("web (a)", 'module.web["a"]', "modules/web/main.tf")


def test_connections_between_instances(estate):
    edges = {(e.source, e.target) for e in planned(estate).edges}
    # the literal index in the code: subnet pub[0] only; each module instance keeps to its own security group
    assert ('module.web["a"].aws_instance.web', "aws_subnet.pub[0]") in edges
    assert ('module.web["a"].aws_instance.web', "aws_subnet.pub[1]") not in edges
    assert ('module.web["a"].aws_instance.web', 'module.web["a"].aws_security_group.web') in edges
    assert ('module.web["a"].aws_instance.web', 'module.web["b"].aws_security_group.web') not in edges
    assert {("aws_subnet.pub[0]", "aws_vpc.v"), ("aws_subnet.pub[1]", "aws_vpc.v")} <= edges


def test_resolved_values_and_instances(estate):
    # the code alone now knows var.public's default (true), so the open CIDR is seen without a plan; the plan adds the
    # instances: one path per module instance, where the code alone has one per block
    without = graph.build(estate, ".")
    assert without.resources["module.web.aws_security_group.web"].body["ingress"][0]["cidr_blocks"] == ['"0.0.0.0/0"']
    assert len(chains.build(without, arch.build(without)).chains) == 1
    g = planned(estate)
    sg = g.resources['module.web["a"].aws_security_group.web'].body
    assert sg["ingress"][0]["cidr_blocks"] == ['"0.0.0.0/0"']
    assert g.resources["aws_subnet.pub[1]"].body["cidr_block"] == '"10.0.1.0/24"'
    r = chains.build(g, arch.build(g))
    assert sorted(c.steps[1] for c in r.chains) == [
        'module.web["a"].aws_instance.web',
        'module.web["b"].aws_instance.web',
    ]


def test_overlay_never_copies_sensitive_or_unknown_values():
    body = {"password": "${var.pw}", "engine": "${var.engine}", "port": "${var.port}", "tags": {"a": '"b"'}}
    values = {"password": "hunter2", "engine": "postgres", "ingress": [{"from_port": 22}]}  # port: unknown, absent
    out = plan.overlay(body, values, {"password": True})
    assert out["password"] == "${var.pw}" and out["port"] == "${var.port}"  # noqa: S105 - test data
    assert out["engine"] == '"postgres"'
    assert out["ingress"] == [{"from_port": 22}]  # a block the code builds with `dynamic`


def test_counted_to_counted_pairs_by_index(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_subnet" "s" {\n  count = 2\n}\n'
        'resource "aws_instance" "i" {\n  count = 2\n  subnet_id = aws_subnet.s[count.index].id\n}\n'
    )

    def res(t, i):
        return {"address": f"{t}[{i}]", "index": i, "values": {}}

    data = {
        "planned_values": {
            "root_module": {
                "resources": [
                    res("aws_subnet.s", 0),
                    res("aws_subnet.s", 1),
                    res("aws_instance.i", 0),
                    res("aws_instance.i", 1),
                ]
            }
        },
        "configuration": {"root_module": {"resources": [{"address": "aws_subnet.s"}, {"address": "aws_instance.i"}]}},
    }
    g = plan.apply(graph.build(tmp_path, "."), data)
    assert {(e.source, e.target) for e in g.edges} == {
        ("aws_instance.i[0]", "aws_subnet.s[0]"),
        ("aws_instance.i[1]", "aws_subnet.s[1]"),
    }


def test_a_state_and_a_plan_for_something_else(tmp_path, estate):
    data = json.loads((estate / "plan.json").read_text())
    state = {"values": data["planned_values"]}  # `terraform show -json` of a state
    assert "aws_subnet.pub[1]" in plan.apply(graph.build(estate, "."), state).resources
    (tmp_path / "other.tf").write_text('resource "aws_s3_bucket" "x" {}\n')
    g = plan.apply(graph.build(tmp_path, "."), data)
    assert list(g.resources) == ["aws_s3_bucket.x"] and "doesn't match" in g.notes[-1]


def test_the_cli(estate, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["map", str(estate), "--no-diagram", "--plan", str(estate / "plan.json")])
    assert e.value.code == cli.EXIT_OK  # a block not deployed is worth knowing, not a gap
    assert "Plan: 4 resource blocks → 7 instances" in capsys.readouterr().out  # the count = 0 bucket is already gone


@pytest.mark.parametrize("bad", ["not json", "[]", '{"planned_values": 3}'])
def test_a_plan_that_isnt_one(estate, capsys, bad):
    (estate / "bad.json").write_text(bad)
    with pytest.raises(SystemExit) as e:
        cli.main(["map", str(estate), "--no-diagram", "--plan", str(estate / "bad.json")])
    assert e.value.code == cli.EXIT_ERROR and "--plan" in capsys.readouterr().err


def test_a_symlinked_plan_is_refused(estate, tmp_path, capsys):
    (tmp_path / "link.json").symlink_to(estate / "plan.json")
    with pytest.raises(SystemExit) as e:
        cli.main(["map", str(estate), "--no-diagram", "--plan", str(tmp_path / "link.json")])
    assert e.value.code == cli.EXIT_ERROR


def test_a_reference_to_one_instance_of_a_module_stays_with_it(tmp_path):
    (tmp_path / "m").mkdir()
    (tmp_path / "m" / "main.tf").write_text(
        'resource "aws_iam_role" "this" {}\noutput "name" {\n  value = aws_iam_role.this.name\n}\n'
    )
    (tmp_path / "main.tf").write_text(
        'module "w" {\n  for_each = toset(["a", "b"])\n  source = "./m"\n}\n'
        'resource "aws_iam_role_policy_attachment" "x" {\n  role = module.w["a"].name\n  policy_arn = "arn"\n}\n'
    )

    def role(k):
        return {"address": f'module.w["{k}"].aws_iam_role.this', "values": {}}

    data = {
        "planned_values": {
            "root_module": {
                "resources": [{"address": "aws_iam_role_policy_attachment.x", "values": {}}],
                "child_modules": [{"address": f'module.w["{k}"]', "resources": [role(k)]} for k in ("a", "b")],
            }
        },
        "configuration": {
            "root_module": {
                "resources": [{"address": "aws_iam_role_policy_attachment.x"}],
                "module_calls": {"w": {"module": {"resources": [{"address": "aws_iam_role.this"}]}}},
            }
        },
    }
    g = plan.apply(graph.build(tmp_path, "."), data)
    assert [e.target for e in g.edges if e.source == "aws_iam_role_policy_attachment.x"] == [
        'module.w["a"].aws_iam_role.this'
    ]


def test_a_jsonencoded_policy_takes_its_planned_value(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "wide" {}\nresource "aws_iam_role" "r" {}\n'
        'resource "aws_iam_role_policy" "p" {\n  role = aws_iam_role.r.id\n'
        '  policy = jsonencode({Statement = [{Effect = "Allow", Action = var.wide ? "s3:*" : "s3:GetObject", '
        'Resource = "*"}]})\n}\n'
    )
    planned = '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}'
    data = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": "aws_iam_role.r", "values": {}},
                    {"address": "aws_iam_role_policy.p", "values": {"policy": planned}},
                ]
            }
        },
        "configuration": {
            "root_module": {"resources": [{"address": "aws_iam_role.r"}, {"address": "aws_iam_role_policy.p"}]}
        },
    }
    g = plan.apply(graph.build(tmp_path, "."), data)
    assert g.resources["aws_iam_role_policy.p"].body["policy"] == f'"{planned}"'  # the object with an expression in it


def test_a_value_only_known_after_apply_keeps_its_expression(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {}\ndata "aws_iam_policy_document" "d" {\n  statement {\n'
        '    actions = ["s3:GetObject"]\n    resources = [aws_s3_bucket.b.arn]\n  }\n}\n'
    )
    data = {
        "planned_values": {
            "root_module": {
                "resources": [
                    {"address": "aws_s3_bucket.b", "values": {}},
                    # the plan writes null for an element it knows only after apply
                    {
                        "address": "data.aws_iam_policy_document.d",
                        "values": {"statement": [{"actions": ["s3:GetObject"], "resources": [None]}]},
                    },
                ]
            }
        },
        "configuration": {
            "root_module": {
                "resources": [{"address": "aws_s3_bucket.b"}, {"address": "data.aws_iam_policy_document.d"}]
            }
        },
    }
    g = plan.apply(graph.build(tmp_path, "."), data)
    assert g.resources["data.aws_iam_policy_document.d"].body["statement"][0]["resources"] == ["${aws_s3_bucket.b.arn}"]
