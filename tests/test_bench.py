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
