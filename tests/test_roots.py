"""Stage 1, the folder in: root modules are found wherever they sit, and told apart from modules."""

import os

import pytest

from terrahunter import cli, deps, roots

PROVIDER = 'provider "aws" {\n  region = "eu-west-1"\n}\n'
BACKEND = 'terraform {\n  backend "s3" {}\n}\n'


def write(base, files: dict[str, str]):
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return base


def kinds(d: roots.Discovery) -> dict[str, str]:
    return {x.path: x.kind for x in d.dirs}


def test_a_folder_that_is_a_root(tmp_path):
    write(tmp_path, {"main.tf": PROVIDER + 'resource "aws_s3_bucket" "b" {}\n'})
    d = roots.discover(tmp_path)
    assert kinds(d) == {".": "root"}
    assert d.roots[0].reasons == ["provider aws"] and d.roots[0].resources == 1


def test_monorepo_roots_deep_down_and_shared_modules(tmp_path):
    call = 'module "net" {\n  source = "../../../modules/net"\n}\n'
    write(
        tmp_path,
        {
            "deploy/prd/infra/main.tf": BACKEND + PROVIDER + call,
            "deploy/dev/infra/main.tf": BACKEND + PROVIDER + call,
            "modules/net/main.tf": 'resource "aws_vpc" "v" {}\n',
            "modules/unused/main.tf": 'variable "x" {}\n',  # nothing to analyse on its own
            "README.md": "not terraform",
        },
    )
    d = roots.discover(tmp_path)
    assert kinds(d) == {"deploy/dev/infra": "root", "deploy/prd/infra": "root", "modules/net": "module"}
    net = next(x for x in d.dirs if x.path == "modules/net")
    assert net.reasons == ["called from deploy/dev/infra", "called from deploy/prd/infra"]
    assert next(x for x in d.roots if x.path == "deploy/prd/infra").reasons == ["backend s3", "provider aws"]


def test_a_module_nested_inside_a_root_is_a_module(tmp_path):
    write(
        tmp_path,
        {
            "stack/main.tf": PROVIDER + 'module "extras" {\n  source = "./extras_dns"\n}\n',
            "stack/extras_dns/main.tf": PROVIDER + 'resource "aws_route53_zone" "z" {}\n',  # a provider, but called
        },
    )
    assert kinds(roots.discover(tmp_path)) == {"stack": "root", "stack/extras_dns": "module"}


def test_opentofu_and_json_files_count(tmp_path):
    write(
        tmp_path,
        {
            "tofu/provider.tofu": PROVIDER,
            "tofu/main.tofu": 'resource "aws_s3_bucket" "b" {}\n',
            "cdk/main.tf.json": '{"provider": {"aws": {"region": "eu-west-1"}}, "terraform": {"backend": {"s3": {}}}}',
        },
    )
    d = roots.discover(tmp_path)
    assert kinds(d) == {"cdk": "root", "tofu": "root"}
    assert next(x for x in d.roots if x.path == "cdk").reasons == ["backend s3", "provider aws"]


def test_deployment_tools_declare_roots(tmp_path):
    write(
        tmp_path,
        {
            ".spacelift/config.yml": "version: 1\nstacks:\n  prd:\n    project_root: stacks/prd\n",
            "atlantis.yaml": "version: 3\nprojects:\n  - dir: stacks/dev\n  - dir: stacks/gone\n",
            "stacks/prd/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
            "stacks/dev/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
        },
    )
    d = roots.discover(tmp_path)
    assert kinds(d) == {"stacks/dev": "root", "stacks/prd": "root"}
    assert next(x for x in d.roots if x.path == "stacks/prd").reasons == ["Spacelift project root"]
    assert any("stacks/gone" in n for n in d.notes)


def test_standalone_configurations_are_listed_not_chosen_over_roots(tmp_path):
    write(tmp_path, {"real/main.tf": PROVIDER, "examples/a/main.tf": 'resource "aws_s3_bucket" "b" {}\n'})
    d = roots.discover(tmp_path)
    assert kinds(d) == {"examples/a": "standalone", "real": "root"}
    assert [x.path for x in cli.select(d, None, False)] == ["real"]


def test_symlinked_directories_are_not_followed(tmp_path):
    outside = write(tmp_path / "outside", {"main.tf": PROVIDER})
    repo = write(tmp_path / "repo", {"main.tf": PROVIDER})
    os.symlink(outside, repo / "linked")
    assert kinds(roots.discover(repo)) == {".": "root"}


def test_a_linked_versions_file_makes_each_environment_a_root(tmp_path):
    # one versions.tf (backend and provider) shared by every environment through symlinks
    repo = write(
        tmp_path / "repo",
        {
            "common/versions.tf": 'terraform {\n  backend "s3" {\n    bucket = "st"\n    key = "x"\n  }\n}\n'
            + PROVIDER,
            "env/dev/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
            "env/prod/main.tf": 'resource "aws_s3_bucket" "b" {}\n',
        },
    )
    for env in ("dev", "prod"):
        os.symlink("../../common/versions.tf", repo / "env" / env / "versions.tf")
    found = kinds(roots.discover(repo))
    assert found["env/dev"] == found["env/prod"] == "root"
    s = deps.survey(repo, "env/prod")
    assert not any("symlink" in n for n in s.notes)


def test_calls_outside_the_folder_are_left_for_later(tmp_path):
    write(tmp_path, {"repo/main.tf": PROVIDER + 'module "x" {\n  source = "../../elsewhere"\n}\n'})
    assert kinds(roots.discover(tmp_path / "repo")) == {".": "root"}


# --- choosing ---------------------------------------------------------------------------------------------------
def two_roots(tmp_path):
    return roots.discover(write(tmp_path, {"a/main.tf": PROVIDER, "b/main.tf": PROVIDER}))


def test_select_by_root_or_all(tmp_path):
    d = two_roots(tmp_path)
    assert [x.path for x in cli.select(d, "b/", False)] == ["b"]
    assert [x.path for x in cli.select(d, None, True)] == ["a", "b"]
    with pytest.raises(cli.TerrahunterError, match="no Terraform files"):
        cli.select(d, "c", False)
    with pytest.raises(cli.TerrahunterError, match="inside the folder"):
        cli.select(d, "../x", False)


def test_several_roots_need_a_choice_when_nobody_is_there_to_ask(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: False)
    with pytest.raises(cli.TerrahunterError, match="--root"):
        cli.select(two_roots(tmp_path), None, False)


def test_several_roots_asks_when_interactive(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_interactive", lambda: True)
    answers = iter(["9", "2"])
    monkeypatch.setattr("builtins.input", lambda *_: next(answers))
    assert [x.path for x in cli.select(two_roots(tmp_path), None, False)] == ["b"]


def test_cli_end_to_end(tmp_path, capsys):
    write(tmp_path, {"deploy/prd/main.tf": BACKEND + PROVIDER})
    with pytest.raises(SystemExit) as e:
        cli.main([str(tmp_path)])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "deploy/prd  (backend s3, provider aws)" in out and "What deploy/prd needs:" in out


def test_folder_names_cannot_inject_terminal_escapes(tmp_path, capsys):
    write(tmp_path, {"evil\x1b]52;c;aGk=\x07/main.tf": PROVIDER})
    with pytest.raises(SystemExit):
        cli.main([str(tmp_path)])
    assert "\x1b" not in capsys.readouterr().out


def test_version(capsys):
    from terrahunter import __version__

    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0 and capsys.readouterr().out.strip() == f"terrahunter {__version__}"
