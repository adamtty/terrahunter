"""Stage 2, what's missing: every module and remote state a root needs is found and classified, nothing is dropped,
and nothing outside the folder (or the --with folders) is read."""

import os

import pytest

from terrahunter import cli, deps

S3_BACKEND = 'terraform {{\n  backend "s3" {{\n    bucket = "state"\n    key    = "{key}"\n  }}\n}}\n'


def write(base, files: dict[str, str]):
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return base


def remote_state(name, key):
    return (
        f'data "terraform_remote_state" "{name}" {{\n  backend = "s3"\n'
        f'  config = {{\n    bucket = "state"\n    key    = "{key}"\n  }}\n}}\n'
    )


def needs(s: deps.Survey) -> dict[str, str]:
    return {n.name: n.status for n in s.needs}


def test_local_modules_are_followed_and_missing_ones_named(tmp_path):
    write(
        tmp_path,
        {
            "deploy/prd/main.tf": 'module "app" {\n  source = "../../modules/app"\n}\n'
            'module "gone" {\n  source = "../../modules/gone"\n}\n',
            "modules/app/main.tf": 'module "inner" {\n  source = "./inner"\n}\n',
            "modules/app/inner/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
        },
    )
    s = deps.survey(tmp_path, "deploy/prd")
    assert needs(s) == {"module.app": "present", "module.inner": "present", "module.gone": "missing"}
    assert next(n for n in s.needs if n.name == "module.inner").via == "module.app"
    assert [n.name for n in s.open] == ["module.gone"]


def test_remote_modules_downloaded_or_not_with_registry_tokens_named(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'
            'module "audit" {\n  source = "registry.example.test/acme/audit/aws"\n}\n',
            ".terraform/modules/modules.json": '{"Modules":[{"Key":"vpc","Source":"x","Dir":".terraform/modules/vpc"}]}',
            ".terraform/modules/vpc/main.tf": 'module "flow" {\n  source = "terraform-aws-modules/flow-logs/aws"\n}\n',
        },
    )
    s = deps.survey(tmp_path, ".")
    assert needs(s) == {"module.vpc": "present", "module.flow": "download", "module.audit": "download"}
    audit = next(n for n in s.needs if n.name == "module.audit")
    assert "TF_TOKEN_registry_example_test" in audit.detail
    assert next(n for n in s.needs if n.name == "module.flow").via == "module.vpc"  # nested, keyed vpc.flow


def test_a_modules_json_pointing_outside_the_root_is_ignored(tmp_path):
    outside = write(tmp_path / "outside", {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'})
    root = write(tmp_path / "repo", {"main.tf": 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'})
    write(root, {".terraform/modules/modules.json": f'{{"Modules":[{{"Key":"vpc","Dir":"{outside}"}}]}}'})
    assert needs(deps.survey(root, ".")) == {"module.vpc": "download"}


def test_expression_sources_and_state_locations_are_unresolved_not_dropped(tmp_path):
    write(
        tmp_path,
        {
            "main.tf": 'module "picked" {\n  source = var.src\n}\n'
            'data "terraform_remote_state" "x" {\n  backend = "s3"\n  config = {\n    bucket = var.b\n'
            '    key = "k"\n  }\n}\n',
        },
    )
    assert needs(deps.survey(tmp_path, ".")) == {
        "module.picked": "unresolved",
        "data.terraform_remote_state.x": "unresolved",
    }


def test_remote_state_is_matched_to_the_stack_that_writes_it(tmp_path):
    write(
        tmp_path,
        {
            "stacks/core/main.tf": S3_BACKEND.format(key="core.tfstate") + 'provider "aws" {}\n',
            "stacks/app/main.tf": remote_state("core", "core.tfstate") + remote_state("nowhere", "gone.tfstate"),
        },
    )
    s = deps.survey(tmp_path, "stacks/app")
    assert needs(s) == {
        "data.terraform_remote_state.core": "matched",
        "data.terraform_remote_state.nowhere": "unmatched",
    }
    core = next(n for n in s.needs if n.name == "data.terraform_remote_state.core")
    assert core.detail == "stacks/core" and core.source == "s3://state/core.tfstate"


def test_another_repository_added_with_with(tmp_path):
    repo = write(
        tmp_path / "platform",
        {
            "app/main.tf": 'module "dns" {\n  source = "../../shared/modules/dns"\n}\n'
            + remote_state("id", "id.tfstate"),
        },
    )
    shared = write(
        tmp_path / "shared",
        {
            "modules/dns/main.tf": 'resource "aws_route53_zone" "z" {}\n',
            "stacks/identity/main.tf": S3_BACKEND.format(key="id.tfstate") + 'provider "aws" {}\n',
        },
    )
    before = deps.survey(repo, "app")
    assert needs(before) == {"module.dns": "outside", "data.terraform_remote_state.id": "unmatched"}
    assert (
        "../shared/modules/dns is outside the folder" in next(n for n in before.needs if n.name == "module.dns").detail
    )
    after = deps.survey(repo, "app", [shared])
    assert needs(after) == {"module.dns": "present", "data.terraform_remote_state.id": "matched"}
    assert next(n for n in after.needs if n.kind == "remote-state").detail == "shared:stacks/identity"


def test_terraform_cloud_workspaces_match_tfe_outputs(tmp_path):
    write(
        tmp_path,
        {
            "billing/main.tf": 'terraform {\n  cloud {\n    organization = "acme"\n    workspaces {\n'
            '      name = "billing-prd"\n    }\n  }\n}\n',
            "app/main.tf": 'data "tfe_outputs" "b" {\n  organization = "acme"\n  workspace = "billing-prd"\n}\n',
        },
    )
    s = deps.survey(tmp_path, "app")
    assert needs(s) == {"data.tfe_outputs.b": "matched"} and s.needs[0].detail == "billing"


def test_json_configuration(tmp_path):
    write(
        tmp_path,
        {
            "core/main.tf.json": '{"terraform": {"backend": {"s3": {"bucket": "state", "key": "core.tfstate"}}}}',
            "app/main.tf.json": '{"module": {"net": {"source": "../net"}}, "data": {"terraform_remote_state": '
            '{"core": {"backend": "s3", "config": {"bucket": "state", "key": "core.tfstate"}}}}}',
            "net/main.tf": 'resource "aws_vpc" "v" {}\n',
        },
    )
    assert needs(deps.survey(tmp_path, "app")) == {
        "module.net": "present",
        "data.terraform_remote_state.core": "matched",
    }


def test_unparseable_files_are_noted(tmp_path):
    write(tmp_path, {"main.tf": 'resource "aws_s3_bucket" "b" {\n', "ok.tf": 'module "m" {\n  source = "./m"\n}\n'})
    s = deps.survey(tmp_path, ".")
    assert any("main.tf" in n and "couldn't be parsed" in n for n in s.notes)
    assert needs(s) == {"module.m": "missing"}


def test_symlinked_module_directories_are_not_read(tmp_path):
    outside = write(tmp_path / "outside", {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'})
    repo = write(tmp_path / "repo", {"main.tf": 'module "m" {\n  source = "./m"\n}\n'})
    os.symlink(outside, repo / "m")
    assert needs(deps.survey(repo, ".")) == {"module.m": "outside"}


# --- fetching, and the CLI ----------------------------------------------------------------------------------------
def test_tool_choice_prefers_opentofu_for_tofu_files(tmp_path, monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda t: f"/bin/{t}")
    write(tmp_path / "a", {"main.tf": ""})
    write(tmp_path / "b", {"main.tofu": ""})
    assert deps.tool_for(tmp_path / "a") == "/bin/terraform"
    assert deps.tool_for(tmp_path / "b") == "/bin/tofu"
    monkeypatch.setattr(deps.shutil, "which", lambda t: None)
    assert deps.fetch(tmp_path / "a") == (False, "neither tofu nor terraform is on PATH")


def test_downloading_needs_consent(tmp_path, monkeypatch, capsys):
    write(tmp_path, {"main.tf": 'provider "aws" {}\nmodule "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'})
    fetched = []
    monkeypatch.setattr(deps, "fetch", lambda d: fetched.append(d) or (True, "get finished"))
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    cli.resolve(tmp_path, ".", [], False)
    assert fetched == []  # said no
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    cli.resolve(tmp_path, ".", [], False)
    assert fetched == [tmp_path.resolve()]
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    fetched.clear()
    cli.resolve(tmp_path, ".", [], False)
    assert fetched == []  # nobody to ask, no --fetch-modules
    cli.resolve(tmp_path, ".", [], True)
    assert fetched == [tmp_path.resolve()]


def test_cli_reports_what_is_missing_and_exits_incomplete(tmp_path, capsys):
    write(tmp_path, {"main.tf": 'provider "aws" {}\nmodule "gone" {\n  source = "./gone"\n}\n'})
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path)])
    out = capsys.readouterr().out
    assert e.value.code == cli.EXIT_INCOMPLETE
    assert "modules       0 of 1 available" in out and "✗ module.gone ./gone" in out


def test_cli_complete_when_nothing_is_missing(tmp_path, capsys):
    write(tmp_path, {"main.tf": 'provider "aws" {}\nresource "aws_s3_bucket" "b" {}\n'})
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path)])
    assert e.value.code == cli.EXIT_OK
    assert "modules       none" in capsys.readouterr().out


def test_with_must_be_a_directory(tmp_path):
    write(tmp_path, {"main.tf": 'provider "aws" {}\n'})
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path), "--with", str(tmp_path / "nope")])
    assert e.value.code == cli.EXIT_ERROR


def test_a_symlinked_download_is_not_read(tmp_path):
    outside = write(tmp_path / "outside", {"main.tf": 'resource "aws_s3_bucket" "b" {}\n'})
    root = write(tmp_path / "repo", {"main.tf": 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'})
    write(root, {".terraform/modules/modules.json": '{"Modules":[{"Key":"vpc","Dir":".terraform/modules/vpc"}]}'})
    os.symlink(outside, root / ".terraform/modules/vpc")
    assert needs(deps.survey(root, ".")) == {"module.vpc": "download"}


def test_a_file_is_parsed_once_and_each_reader_gets_its_own_copy(tmp_path, monkeypatch):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
    (tmp_path / "bad.tf").write_text("resource {{{\n")
    calls = []
    real = deps._hcl
    monkeypatch.setattr(deps, "_hcl", lambda text: calls.append(text) or real(text))
    deps._PARSED.clear()
    first = deps.load_dir(tmp_path, notes := [], ".")
    second = deps.load_dir(tmp_path, notes2 := [], ".")
    assert len(calls) == 2  # each distinct text once, the bad one included
    assert first[0][1] == second[0][1] and first[0][1] is not second[0][1]
    assert any("bad.tf" in n for n in notes) and any("bad.tf" in n for n in notes2)  # still reported every time
