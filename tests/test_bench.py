"""scripts/bench.py: terrahunter's attack paths scored against a knowledge-base answer key."""

import importlib.util
import json
from pathlib import Path

from test_chains import BUCKETS, NET, ROLE, WILDCARD_S3, instance, sg

spec = importlib.util.spec_from_file_location("bench", Path(__file__).parents[1] / "scripts" / "bench.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def kb(tmp_path, key: list[dict]) -> Path:
    project = tmp_path / "kb" / "downloads" / "bench" / "demo" / "infra"
    project.mkdir(parents=True)
    (project / "main.tf").write_text(
        NET
        + ROLE
        + BUCKETS
        + WILDCARD_S3
        + sg("web", 80)
        + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n")
        + 'resource "aws_s3_bucket" "site" {\n  acl = "public-read"\n}\n'
    )
    (tmp_path / "kb" / "bench" / "demo").mkdir(parents=True)
    (tmp_path / "kb" / "bench" / "demo" / "expected.json").write_text(json.dumps(key))
    return tmp_path / "kb"


def path(pid, entry, reaches, steps=None):
    return {
        "id": pid,
        "entry": entry,
        "steps": steps or ["internet", entry],
        "reaches": [{"resource": r, "access": "admin", "sensitive": False} for r in reaches],
        "why": "because",
        "confidence": "likely",
    }


def test_recall_precision_and_contradictions(tmp_path, capsys):
    key = [
        {
            "root": "infra",
            "paths": [
                path("D-01", "aws_instance.web", ["aws_s3_bucket.logs", "aws_s3_bucket.customer_exports"]),
                path("D-02", "aws_lb.missing", ["aws_s3_bucket.logs"]),
                path("D-03", "aws_iam_role.app", [], steps=["attacker-principal", "aws_iam_role.app"]),
            ],
            "not_paths": [{"resource": "aws_s3_bucket.site", "why": "public, but it holds nothing"}],
        }
    ]
    folder = kb(tmp_path, key)
    out = tmp_path / "r.json"
    assert bench.main(["--kb", str(folder), "--json", str(out)]) == 0
    t = json.loads(out.read_text())["totals"]
    assert (t["expected"], t["found"], t["given_credentials"]) == (2, 1, 1)
    assert t["reach_recall"] == 1.0  # both buckets
    assert t["contradicted"] == 1 and t["matched"] == 1  # the public bucket is the key's not_path
    text = capsys.readouterr().out
    assert "**missed** D-02" in text and "public, but it holds nothing" in text


def test_nothing_fetched(tmp_path, capsys):
    (tmp_path / "kb" / "bench" / "demo").mkdir(parents=True)
    (tmp_path / "kb" / "bench" / "demo" / "expected.json").write_text("[]")
    assert bench.main(["--kb", str(tmp_path / "kb")]) == 2
    assert "not fetched" in capsys.readouterr().err


def test_a_key_may_name_what_opens_the_entry(tmp_path):
    # a public container is drawn on its storage account; the key names the container
    text = (
        'resource "azurerm_storage_account" "sa" {\n  name = "sa"\n}\n'
        'resource "azurerm_storage_container" "c" {\n  storage_account_name = azurerm_storage_account.sa.name\n'
        '  container_access_type = "blob"\n}\n'
    )
    (tmp_path / "main.tf").write_text(text)
    row = bench.score_root(tmp_path, {"root": ".", "paths": [path("Z-01", "azurerm_storage_container.c", [])]})
    assert row["expected"][0]["found"]


def test_given_credentials_are_scored_from_the_start_identity(tmp_path):
    key = [
        {
            "root": "infra",
            "paths": [
                path(
                    "G-01", "aws_iam_role.app", ["aws_s3_bucket.logs"], steps=["attacker-principal", "aws_iam_role.app"]
                ),
                # reaching only itself isn't found: the start doesn't count as gained
                path(
                    "G-02", "aws_iam_role.app", ["aws_iam_role.app"], steps=["attacker-principal", "aws_iam_role.app"]
                ),
            ],
            "not_paths": [],
        }
    ]
    folder = kb(tmp_path, key)
    out = tmp_path / "r.json"
    assert bench.main(["--kb", str(folder), "--json", str(out)]) == 0
    t = json.loads(out.read_text())["totals"]
    assert (t["given_credentials"], t["given_found"]) == (2, 1)


def test_an_estate_with_other_account_paths_and_findings(tmp_path):
    root = tmp_path / "est" / "app-repo" / "env" / "prd"
    root.mkdir(parents=True)
    (root / "main.tf").write_text(
        'resource "aws_s3_bucket" "site" {\n  acl = "public-read"\n}\n'
        'resource "aws_iam_role" "vendor" {\n  assume_role_policy = jsonencode({Statement = [{Effect = "Allow", '
        'Action = "sts:AssumeRole", Principal = {AWS = "arn:aws:iam::111122223333:root"}}]})\n}\n'
        'resource "aws_ssm_parameter" "token" {\n  type = "SecureString"\n  value = "k3y-7Qf3mK9pL2vX8cN4"\n}\n'
        'resource "aws_ssm_parameter" "label" {\n  type = "String"\n  value = "token=not-a-secret-at-all"\n}\n'
    )
    (tmp_path / "est" / "bench").mkdir()
    (tmp_path / "est" / "bench" / "source.yaml").write_text(
        "name: est\ncloud: aws\nroots:\n  - path: app-repo/env/prd\n    variables: {env: prd}\n    plan: null\n"
    )
    key = {
        "root": "app-repo/env/prd",
        "paths": [
            {
                "id": "P1",
                "entry": "aws_s3_bucket.site",
                "steps": ["internet", "aws_s3_bucket.site"],
                "reaches": [],
                "why": "",
                "evidence": [],
                "confidence": "certain",
            },
            {
                "id": "P2",
                "entry": "aws_iam_role.vendor",
                "steps": ["other-account", "aws_iam_role.vendor"],
                "reaches": [],
                "why": "",
                "evidence": [],
                "confidence": "possible",
            },
        ],
        "not_paths": [],
        "findings": [{"id": "F1", "kind": "hardcoded-secret", "resource": "aws_ssm_parameter.token"}],
        "not_findings": [{"id": "N1", "kind": "hardcoded-secret", "resource": "aws_ssm_parameter.label"}],
    }
    (tmp_path / "est" / "bench" / "expected.json").write_text(json.dumps([key]))
    t = bench.totals(bench.score_estate(tmp_path / "est"))
    assert (t["found"], t["expected"]) == (1, 1)
    assert (t["outside_found"], t["outside"], t["findings_found"], t["findings"], t["false_findings"]) == (
        1,
        1,
        1,
        1,
        0,
    )
