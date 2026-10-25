"""Estate mode: every root in one graph, with accounts and projects kept apart."""

import pytest

from terrahunter import cli, deps, estate, graph, iam


def build(tmp_path, roots):
    graphs = {}
    for root, text in roots.items():
        d = tmp_path / root
        d.mkdir(parents=True)
        (d / "main.tf").write_text(text)
        graphs[root] = graph.build(d, ".")
    return estate.merge(graphs)


def aws(account, body):
    return f'locals {{\n  account_id = "{account}"\n}}\n' + body


READER = """
resource "aws_iam_role" "intake" {
  name = "intake"
}
resource "aws_iam_role_policy" "read" {
  role   = aws_iam_role.intake.id
  policy = jsonencode({Statement = [{Effect = "Allow", Action = "s3:GetObject", Resource = "*"}]})
}
"""
BUCKET = 'resource "aws_s3_bucket" "drop" {\n  bucket = "partner-drop"\n}\n'
ROLE = 'module.root["edge"].aws_iam_role.intake'
DROP = 'module.root["vault"].aws_s3_bucket.drop'


def test_addresses_carry_their_root(tmp_path):
    g = build(tmp_path, {"edge": READER, "vault": BUCKET})
    assert ROLE in g.resources and DROP in g.resources
    assert g.resources[ROLE].module == 'module.root["edge"]'
    assert estate.root_of(DROP) == "vault"
    assert estate.local(DROP) == "aws_s3_bucket.drop"
    assert estate.label(DROP) == "vault: aws_s3_bucket.drop"
    assert estate.root_of("aws_s3_bucket.drop") == ""
    assert estate.root_of(estate.tag('a"b') + ".x") == 'a"b'


def test_roots_that_name_no_account_are_kept_apart(tmp_path):
    g = build(tmp_path, {"edge": READER, "vault": BUCKET})
    assert g.accounts == {"edge": "", "vault": ""}
    assert not estate.same_account(g, ROLE, DROP)
    assert iam.Model(g).access(ROLE, DROP, "s3") == ""


def test_a_wildcard_grant_reaches_its_own_account_only(tmp_path):
    g = build(tmp_path, {"edge": aws("111111111111", READER), "vault": aws("111111111111", BUCKET)})
    assert estate.same_account(g, ROLE, DROP)
    assert iam.Model(g).access(ROLE, DROP, "s3") == "read"

    g = build(tmp_path / "2", {"edge": aws("111111111111", READER), "vault": aws("222222222222", BUCKET)})
    assert g.accounts == {"edge": "111111111111", "vault": "222222222222"}
    assert iam.Model(g).allowed(ROLE, "s3:GetObject", DROP) is False


def test_a_bucket_policy_naming_the_role_lets_it_across(tmp_path):
    policy = """
resource "aws_s3_bucket_policy" "drop" {
  bucket = aws_s3_bucket.drop.id
  policy = jsonencode({Statement = [{Effect = "Allow", Action = "s3:GetObject", Resource = "${aws_s3_bucket.drop.arn}/*",
    Principal = {AWS = "arn:aws:iam::111111111111:role/intake"}}]})
}
"""
    g = build(tmp_path, {"edge": aws("111111111111", READER), "vault": aws("222222222222", BUCKET + policy)})
    assert iam.Model(g).access(ROLE, DROP, "s3") == "read"


def test_project_wide_grants_stay_in_their_project(tmp_path):
    def project(p, extra=""):
        return (
            f'resource "google_storage_bucket" "b" {{\n  name = "{p}-b"\n  project = "{p}"\n}}\n'
            f'resource "google_service_account" "sa" {{\n  account_id = "sa"\n  project = "{p}"\n}}\n' + extra
        )

    grant = """
resource "google_project_iam_member" "admin" {
  project = "lab"
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.sa.email}"
}
"""
    g = build(tmp_path, {"lab": project("lab", grant), "prod": project("prod")})
    assert g.accounts == {"lab": "gcp:lab", "prod": "gcp:prod"}
    m = iam.GcpModel(g)
    sa = 'module.root["lab"].google_service_account.sa'
    assert m.access(sa, 'module.root["lab"].google_storage_bucket.b')
    assert m.access(sa, 'module.root["prod"].google_storage_bucket.b') == ""


def test_cli_analyses_the_estate_as_one(tmp_path, monkeypatch, capsys):
    for root, text in {"edge": aws("111111111111", READER), "vault": aws("111111111111", BUCKET)}.items():
        (tmp_path / "repo" / root).mkdir(parents=True)
        (tmp_path / "repo" / root / "main.tf").write_text('provider "aws" {}\n' + text)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path / "repo"), "--estate", "--no-scan"])
    out = capsys.readouterr().out
    assert "Estate: 2 roots analysed together" in out
    assert {p.name for p in tmp_path.glob("*.html")} == {"terrahunter-diagram.html"}


def linked(tmp_path, roots):
    for root, text in roots.items():
        (tmp_path / root).mkdir(parents=True)
        (tmp_path / root / "main.tf").write_text(text)
    graphs = {r: graph.build(tmp_path, r) for r in roots}
    g = estate.merge(graphs)
    return g, estate.link(g, {r: deps.survey(tmp_path, r) for r in roots})


def reader(resource):
    return f"""
resource "aws_iam_role" "app" {{
  name = "app"
}}
resource "aws_iam_role_policy" "read" {{
  role   = aws_iam_role.app.id
  policy = jsonencode({{Statement = [{{Effect = "Allow", Action = "s3:GetObject", Resource = "${{{resource}}}/*"}}]}})
}}
"""


APP = 'module.root["app"].aws_iam_role.app'


def test_a_remote_state_output_is_the_other_roots_resource(tmp_path):
    net = """
terraform {
  backend "s3" {
    bucket = "state"
    key    = "data.tfstate"
  }
}
resource "aws_s3_bucket" "d" {}
resource "aws_s3_bucket" "other" {}
output "bucket_arn" {
  value = aws_s3_bucket.d.arn
}
"""
    state = (
        'data "terraform_remote_state" "data" {\n  backend = "s3"\n'
        '  config = {\n    bucket = "state"\n    key    = "data.tfstate"\n  }\n}\n'
    )
    app = aws("111111111111", state + reader("data.terraform_remote_state.data.outputs.bucket_arn"))
    g, links = linked(tmp_path, {"data": aws("111111111111", net), "app": app})
    assert links == ["app: data.terraform_remote_state.data → data: aws_s3_bucket.d"]
    assert {e.output for e in g.edges if e.target.endswith("terraform_remote_state.data")} == {"bucket_arn"}
    m = iam.Model(g)
    assert m.access(APP, 'module.root["data"].aws_s3_bucket.d', "s3") == "read"
    assert m.access(APP, 'module.root["data"].aws_s3_bucket.other', "s3") == ""


def test_a_lookup_by_name_is_the_other_roots_resource(tmp_path):
    app = aws(
        "111111111111",
        'data "aws_s3_bucket" "d" {\n  bucket = "partner-drop"\n}\n' + reader("data.aws_s3_bucket.d.arn"),
    )
    vault = aws("111111111111", BUCKET + 'resource "aws_s3_bucket" "x" {\n  bucket = "another"\n}\n')
    g, links = linked(tmp_path, {"app": app, "vault": vault})
    assert links == ["app: data.aws_s3_bucket.d → vault: aws_s3_bucket.drop"]
    assert any(e.source.endswith("aws_iam_role_policy.read") and e.target == DROP for e in g.edges)
    m = iam.Model(g)
    assert m.access(APP, DROP, "s3") == "read"
    assert m.access(APP, 'module.root["vault"].aws_s3_bucket.x', "s3") == ""


def test_trusts_across_accounts(tmp_path):
    def target(principal):
        return aws(
            "222222222222",
            'resource "aws_iam_role" "target" {\n  assume_role_policy = jsonencode({Statement = [{Effect = "Allow", '
            f'Action = "sts:AssumeRole", Principal = {{AWS = "{principal}"}}}}]}})\n}}\n',
        )

    assume = """
resource "aws_iam_role_policy" "assume" {
  role   = aws_iam_role.intake.id
  policy = jsonencode({Statement = [{Effect = "Allow", Action = "sts:AssumeRole", Resource = "*"}]})
}
"""
    role = 'resource "aws_iam_role" "intake" {\n  name = "intake"\n}\n'
    tgt = 'module.root["vault"].aws_iam_role.target'
    for i, (principal, grant, expected) in enumerate(
        [
            ("arn:aws:iam::111111111111:role/intake", assume, True),
            ("arn:aws:iam::111111111111:role/intake", "", False),  # across accounts, its own policy must allow it
            ("arn:aws:iam::111111111111:root", assume, True),
            ("arn:aws:iam::333333333333:root", assume, False),  # another account's root
            ("arn:aws:iam::333333333333:role/intake", assume, False),  # same name, another account
        ]
    ):
        g = build(tmp_path / str(i), {"edge": aws("111111111111", role + grant), "vault": target(principal)})
        assert iam.Model(g).can_assume(ROLE, tgt) is expected, principal


def test_shown_reads_as_root_and_address():
    assert estate.shown('Internet → module.root["edge/prod"].module.site.aws_s3_bucket.x') == (
        "Internet → edge/prod: module.site.aws_s3_bucket.x"
    )
    assert estate.shown("aws_s3_bucket.x") == "aws_s3_bucket.x"


def test_the_diagram_groups_roots_by_account_and_repository(tmp_path):
    from terrahunter import arch

    g = build(
        tmp_path,
        {
            "edge/prod": aws("111111111111", READER),
            "edge/dev": aws("111111111111", READER),
            "vault/prod": aws("222222222222", BUCKET),
        },
    )
    m = arch.build(g)
    conts = {c.id: c for c in m.containers}
    assert conts["account:111111111111"].label == "AWS account 111111111111"
    assert conts["repo:111111111111:edge"].parent == "account:111111111111"
    assert conts["root:edge/dev"].parent == conts["root:edge/prod"].parent == "repo:111111111111:edge"
    comps = {c.id: c for c in m.components}

    def outer(addr):
        chain, c = [], comps[addr].parent
        while c:
            chain.append(c)
            c = conts[c].parent
        return chain[-3:]

    assert outer('module.root["vault/prod"].aws_s3_bucket.drop') == [
        "root:vault/prod",
        "repo:222222222222:vault",
        "account:222222222222",
    ]
    assert outer('module.root["edge/dev"].aws_iam_role.intake')[0] == "root:edge/dev"
