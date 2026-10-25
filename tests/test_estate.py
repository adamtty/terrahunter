"""Estate mode: every root in one graph, with accounts and projects kept apart."""

import pytest

from terrahunter import cli, estate, graph, iam


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
