"""Stage 6, the results: the fix list (what breaks which paths, and where), the Markdown report, and --fail-on."""

import json

import pytest
from test_chains import BUCKETS, NET, ROLE, WILDCARD_S3, instance, sg

from terrahunter import arch, chains, cli, graph, report

PROFILE = "  iam_instance_profile = aws_iam_instance_profile.app.name\n"


def build(tmp_path, text: str):
    (tmp_path / "main.tf").write_text(text)
    g = graph.build(tmp_path, ".")
    m = arch.build(g)
    return g, m, chains.build(g, m)


def test_fixes_say_what_breaks_which_path_and_where(tmp_path):
    _, _, r = build(
        tmp_path,
        NET
        + ROLE
        + BUCKETS
        + WILDCARD_S3
        + sg("web", 80)
        + instance("a", "pub", "web", PROFILE)
        + instance("b", "pub", "web", PROFILE)
        + sg("db", 5432)
        + 'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n'
        "  vpc_security_group_ids = [aws_security_group.db.id]\n}\n",
    )
    by = {f.id.split(":")[0]: f for f in r.fixes}
    close = by["close"]  # one security group, two instances: one change breaks both paths
    assert close.effect == "breaks" and len(close.chains) == 2
    assert [w["address"] for w in close.where] == ["aws_security_group.web"] and close.where[0]["line"] > 0
    assert by["scope"].effect == "narrows" and by["scope"].where[0]["address"] == "aws_iam_role_policy.p"
    assert by["imds"].effect == "hardens"
    assert by["public"].where[0]["address"] == "aws_db_instance.db"
    order = [f.effect for f in r.fixes]  # removing a path before narrowing or hardening one
    assert order.index("breaks") < order.index("narrows") < order.index("hardens")
    assert all(c.fixes for c in r.chains)


def test_a_separate_rule_is_where_the_port_is_closed(tmp_path):
    _, _, r = build(
        tmp_path,
        NET
        + sg("web")
        + 'resource "aws_security_group_rule" "ssh" {\n  type = "ingress"\n  from_port = 22\n  to_port = 22\n'
        '  cidr_blocks = ["0.0.0.0/0"]\n  security_group_id = aws_security_group.web.id\n}\n'
        + 'resource "aws_ebs_volume" "v" {}\n'
        + instance("a", "pub", "web")
        + 'resource "aws_volume_attachment" "att" {\n  instance_id = aws_instance.a.id\n  volume_id = aws_ebs_volume.v.id\n}\n',
    )
    (f,) = [f for f in r.fixes if f.id.startswith("close")]
    assert f.action == "Close 22 to the internet in security group web"
    assert [w["address"] for w in f.where] == ["aws_security_group_rule.ssh"]


def test_the_report_escapes_what_came_from_the_folder(tmp_path):
    evil = "x`|<img src=x onerror=alert(1)>*_[a](javascript:b)"
    g, m, r = build(
        tmp_path, NET + ROLE + BUCKETS + WILDCARD_S3 + sg("web", 80) + instance("web", "pub", "web", PROFILE)
    )
    m.components[0].name = evil  # names can't carry this (HCL labels), but scanner text and paths can
    s = deps_survey(tmp_path)
    text = report.render("repo <b>|`", [report.RootResult(".", s, g, m, None, r)])
    assert "<img" not in text and "<b>" not in text and "](javascript" not in text
    assert "#### 1. CRITICAL · likely · The internet → web → app → 2 data stores" in text
    assert "### Fix first" in text and "| 1 | Close 80 to the internet in security group web |" in text
    assert report.code("a`b|c") == "`a'b\\|c`"
    assert report.md("1. not a list") == "1\\. not a list"


def deps_survey(path):
    from terrahunter import deps

    return deps.survey(path, ".", [])


@pytest.mark.parametrize(("fail_on", "code"), [("critical", cli.EXIT_PATHS), ("high", cli.EXIT_PATHS), (None, 0)])
def test_fail_on_and_the_report_file(tmp_path, fail_on, code):
    (tmp_path / "main.tf").write_text(
        NET + ROLE + BUCKETS + WILDCARD_S3 + sg("web", 80) + instance("web", "pub", "web", PROFILE)
    )
    out, js = tmp_path / "r.md", tmp_path / "g.json"
    args = [str(tmp_path), "--no-scan", "--no-diagram", "--report", str(out), "--graph-json", str(js)]
    with pytest.raises(SystemExit) as e:
        cli.main(args + (["--fail-on", fail_on] if fail_on else []))
    assert e.value.code == code
    assert out.read_text().startswith("# terrahunter report:")
    assert json.loads(js.read_text())["graphs"][0]["fixes"][0]["effect"] == "breaks"


def test_fail_on_ignores_milder_paths(tmp_path):
    (tmp_path / "main.tf").write_text(NET + sg("web", 22) + instance("web", "pub", "web"))  # SSH only: medium
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path), "--no-scan", "--no-diagram", "--fail-on", "high"])
    assert e.value.code == cli.EXIT_OK
