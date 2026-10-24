"""Stage 3b, the architecture model and the diagram: what's drawn, where, with which badges and connections; and
the page is self-contained, script-locked and safe with hostile values in it."""

import base64
import hashlib
import json
import re

import pytest

from terrahunter import arch, cli, diagram, graph


def write(base, files: dict[str, str]):
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return base


NET = """
resource "aws_vpc" "v" { cidr_block = "10.0.0.0/16" }
resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.v.id }
resource "aws_route_table" "pub" { vpc_id = aws_vpc.v.id }
resource "aws_route" "out" {
  route_table_id = aws_route_table.pub.id
  gateway_id     = aws_internet_gateway.igw.id
}
resource "aws_subnet" "pub" {
  vpc_id            = aws_vpc.v.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "${var.region}a"
}
resource "aws_subnet" "priv" { vpc_id = aws_vpc.v.id }
resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.pub.id
  route_table_id = aws_route_table.pub.id
}
"""


def model(tmp_path, extra: str) -> arch.Model:
    write(tmp_path, {"main.tf": NET + extra})
    return arch.build(graph.build(tmp_path, "."))


def comp(m: arch.Model, addr: str) -> arch.Component:
    return next(c for c in m.components if c.id == addr)


def conns(m: arch.Model) -> set[tuple[str, str, str]]:
    return {(c.source, c.target, c.label) for c in m.connections}


def test_subnets_are_public_when_routed_to_an_internet_gateway(tmp_path):
    m = model(tmp_path, "")
    subnets = {c.id: c for c in m.containers if c.kind == "subnet"}
    assert subnets["aws_subnet.pub"].public and not subnets["aws_subnet.priv"].public
    assert subnets["aws_subnet.pub"].az == "AZ a" and subnets["aws_subnet.pub"].parent == "aws_vpc.v"


def test_components_sit_where_their_references_put_them_with_badges(tmp_path):
    m = model(
        tmp_path,
        """
resource "aws_security_group" "web" {
  vpc_id = aws_vpc.v.id
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group_rule" "https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.web.id
}
resource "aws_instance" "web" {
  subnet_id                   = aws_subnet.pub.id
  vpc_security_group_ids      = [aws_security_group.web.id]
  associate_public_ip_address = true
}
resource "aws_s3_bucket" "b" { acl = "public-read" }
""",
    )
    web = comp(m, "aws_instance.web")
    assert web.parent == "aws_subnet.pub"
    assert [b.text for b in web.badges] == ["open to internet: 22, 443", "public IP", "IMDSv1 allowed"]
    assert all(b.risk for b in web.badges)
    assert comp(m, "aws_s3_bucket.b").parent == "regional"
    assert "aws_security_group.web" not in {c.id for c in m.components}  # plumbing: a badge, not a box


def test_identity_plumbing_collapses_into_runs_as_and_badges(tmp_path):
    m = model(
        tmp_path,
        """
resource "aws_iam_role" "r" {}
resource "aws_iam_instance_profile" "p" { role = aws_iam_role.r.name }
resource "aws_instance" "web" {
  subnet_id            = aws_subnet.priv.id
  iam_instance_profile = aws_iam_instance_profile.p.name
  metadata_options { http_tokens = "required" }
}
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.r.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_user" "u" {}
resource "aws_iam_access_key" "k" { user = aws_iam_user.u.name }
""",
    )
    assert ("aws_instance.web", "aws_iam_role.r", "runs as") in conns(m)
    assert comp(m, "aws_instance.web").badges == []  # IMDSv2 required: nothing to say
    assert [(b.text, b.risk) for b in comp(m, "aws_iam_role.r").badges] == [("AdministratorAccess", True)]
    # the knowledge base adds that the key's secret is in the state
    assert [b.text for b in comp(m, "aws_iam_user.u").badges] == [
        "long-lived access key",
        "secret key in Terraform state",
    ]
    assert comp(m, "aws_iam_role.r").parent == "global"


def test_load_balancer_plumbing_collapses_into_routes_to(tmp_path):
    m = model(
        tmp_path,
        """
resource "aws_lb" "alb" { subnets = [aws_subnet.pub.id] }
resource "aws_lb_target_group" "tg" { vpc_id = aws_vpc.v.id }
resource "aws_lb_listener" "l" {
  load_balancer_arn = aws_lb.alb.arn
  default_action { target_group_arn = aws_lb_target_group.tg.arn }
}
resource "aws_instance" "app" { subnet_id = aws_subnet.priv.id }
resource "aws_lb_target_group_attachment" "a" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.app.id
}
""",
    )
    assert ("aws_lb.alb", "aws_instance.app", "routes to") in conns(m)


def test_names_and_tags_are_not_connections(tmp_path):
    m = model(
        tmp_path,
        """
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {
  bucket = "copy-of-${aws_s3_bucket.a.id}"
  tags   = { Source = aws_s3_bucket.a.id }
}
""",
    )
    assert not conns(m)


def test_unknown_modules_are_dashed_placeholders_with_their_edges(tmp_path):
    m = model(
        tmp_path,
        'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'
        'resource "aws_instance" "web" {\n  subnet_id = module.vpc.private_subnets[0]\n}\n',
    )
    u = comp(m, "module.vpc")
    assert u.unknown and u.parent == "unknown" and "not downloaded" in u.badges[0].text
    assert ("aws_instance.web", "module.vpc", "runs in") in conns(m)


# --- the page ------------------------------------------------------------------------------------------------------
def test_the_page_is_self_contained_and_its_script_is_hash_locked(tmp_path):
    page = diagram.render(model(tmp_path, ""), "demo")
    assert not re.search(r"<script[^>]+src=|<link[^>]+href=|https?://(?!www\.w3\.org)", page)
    csp = re.search(r"script-src 'sha256-([^']+)'", page).group(1)
    body = re.search(r"<script>(.*?)</script>", page, re.DOTALL).group(1)
    assert csp == base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
    assert "default-src 'none'" in page


def test_hostile_values_cannot_break_out_of_the_data(tmp_path):
    m = model(
        tmp_path,
        'resource "aws_security_group" "x" {\n  ingress {\n    from_port = "</script><script>alert(1)</script>"\n'
        '    to_port = 1\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        'resource "aws_instance" "i" { vpc_security_group_ids = [aws_security_group.x.id] }\n',
    )
    page = diagram.render(m, "</title><script>x</script>")
    assert page.count("<script") == 2  # the data element and the one script: nothing injected
    data = re.search(r'<script id="data" type="application/json">(.*?)</script>', page, re.DOTALL).group(1)
    inst = next(c for c in json.loads(data)["comps"] if c["id"] == "aws_instance.i")
    assert "alert(1)" in inst["badges"][0]["text"]  # kept as data, shown as text


def test_cli_writes_the_diagram(tmp_path, monkeypatch, capsys):
    write(tmp_path / "repo", {"main.tf": 'provider "aws" {}\n' + NET})
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path / "repo")])
    assert e.value.code == cli.EXIT_OK and (tmp_path / "terrahunter-diagram.html").exists()
    assert "diagram: terrahunter-diagram.html" in capsys.readouterr().out
    (tmp_path / "terrahunter-diagram.html").unlink()
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path / "repo"), "--no-diagram"])
    assert not (tmp_path / "terrahunter-diagram.html").exists()


def test_one_diagram_per_root_with_all_roots(tmp_path, monkeypatch):
    write(tmp_path / "repo", {"a/main.tf": 'provider "aws" {}\n', "b/main.tf": 'provider "aws" {}\n'})
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path / "repo"), "--all-roots"])
    assert {p.name for p in tmp_path.glob("*.html")} == {"terrahunter-diagram-a.html", "terrahunter-diagram-b.html"}
