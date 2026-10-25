"""Hard-coded secrets and long-lived keys: literals where secrets go, never variables or placeholders."""

import json

import pytest

from terrahunter import cli, graph, secrets


def found(tmp_path, text, name="main.tf"):
    (tmp_path / name).write_text(text)
    return {(f.id, f.address) for f in secrets.find(graph.build(tmp_path, "."))}


@pytest.mark.parametrize(
    ("text", "hit"),
    [
        # a SecureString with a credential-like literal: "example" in it doesn't make it a placeholder
        (
            'resource "aws_ssm_parameter" "t" {\n  type = "SecureString"\n  value = "real-example-7Qf3mK9pL2vX8cN4"\n}\n',
            True,
        ),
        # a plain String parameter is configuration, whatever it says
        ('resource "aws_ssm_parameter" "t" {\n  type = "String"\n  value = "access_token=hunter2hunter2"\n}\n', False),
        # from a variable with no default: the real value is set elsewhere
        (
            (
                'variable "p" {\n  sensitive = true\n}\nresource "aws_rds_cluster" "c" {\n  master_password = var.p\n'
                "  lifecycle {\n    ignore_changes = [master_password]\n  }\n}\n"
            ),
            False,
        ),
        # placeholders
        (
            (
                'resource "aws_secretsmanager_secret_version" "v" {\n'
                '  secret_string = jsonencode({username = "TODO-set-by-ci", token = "0xCAFE-not-a-real-value"})\n}\n'
            ),
            False,
        ),
        ('resource "aws_db_instance" "d" {\n  password = "CHANGEME"\n}\n', False),
        ('resource "aws_db_instance" "d" {\n  password = "Pr0d-db-9xV2qL7mT4"\n}\n', True),
        # a function's variables named like credentials
        (
            (
                'resource "aws_lambda_function" "f" {\n  environment {\n    variables = {\n'
                '      JWT_SECRET = "s3cr3t-signing-k3y-9921"\n      REGION = "eu-west-1"\n    }\n  }\n}\n'
            ),
            True,
        ),
    ],
)
def test_literals_where_secrets_go(tmp_path, text, hit):
    assert any(i == "TH-SECRET" for i, _ in found(tmp_path, text)) is hit


def test_provider_credentials_and_access_keys(tmp_path):
    out = found(
        tmp_path,
        'provider "aws" {\n  access_key = "AKIAIOSFODNN7EXAMPLE"\n'
        '  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n}\n'
        'resource "aws_iam_user" "u" {}\nresource "aws_iam_access_key" "k" {\n  user = aws_iam_user.u.name\n}\n'
        'resource "aws_iam_access_key" "off" {\n  user = aws_iam_user.u.name\n  status = "Inactive"\n}\n',
        name="provider.tofu",
    )
    assert out == {("TH-SECRET", "provider.aws"), ("TH-KEY", "aws_iam_access_key.k")}


def test_a_value_given_on_the_command_line_isn_t_in_the_code(tmp_path):
    (tmp_path / "main.tf").write_text(
        'variable "token" {\n  sensitive = true\n}\n'
        'resource "aws_ssm_parameter" "t" {\n  type = "SecureString"\n  value = var.token\n}\n'
    )
    given = graph.build(tmp_path, ".", variables={"token": '"supplied-at-plan-7Qf3mK9pL2"'})
    written = graph.build(tmp_path, ".")
    assert secrets.find(given) and not secrets.find(written)  # the CLI looks at the configuration as written


def test_the_cli_reports_only_secrets_written_in_the_code(tmp_path):
    (tmp_path / "main.tf").write_text(
        'provider "aws" {}\nvariable "token" {\n  sensitive = true\n}\n'
        'resource "aws_ssm_parameter" "t" {\n  type = "SecureString"\n  value = var.token\n}\n'
        'resource "aws_ssm_parameter" "lit" {\n  type = "SecureString"\n  value = "written-in-code-7Qf3mK9pL2"\n}\n'
    )
    out = tmp_path / "g.json"
    with pytest.raises(SystemExit):
        cli.main(
            [
                str(tmp_path),
                "--no-scan",
                "--no-diagram",
                "--var",
                "token=supplied-at-plan-7Qf3mK9pL2",
                "--graph-json",
                str(out),
            ]
        )
    found = {f["resource"] for f in json.loads(out.read_text())["graphs"][0]["scan"]["findings"]}
    assert found == {"aws_ssm_parameter.lit"}
