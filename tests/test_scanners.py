"""Stage 4, vulnerabilities: the scanners see a contained copy of exactly what the graph read, and every finding
lands on the resource it's about, in every instance of a module, or is reported as not placed."""

import shutil
from pathlib import Path

import pytest

from terrahunter import arch, cli, diagram, graph, sandbox, scanners

ROOT = 'provider "aws" {}\n'
WEB = (
    'variable "name" {}\n\nresource "aws_security_group" "web" {\n  name = var.name\n'
    '  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n\n'
    'output "sg" { value = aws_security_group.web.id }\n'
)


def write(base: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return base


def raw(source="trivy", **kw) -> dict:
    return {"id": "X-1", "title": "a problem", "severity": "HIGH", "resource": "", "file": "main.tf", "line": 1} | {
        "source": source,
        **kw,
    }


def runners(monkeypatch, trivy=(), checkov=(), seen=None):
    """Fake scanners returning these raw findings; `seen` collects the staged files each one was shown."""

    def make(found):
        def run(scan_dir, work):
            if seen is not None:
                base = Path(scan_dir)
                while base.name != "target":
                    base = base.parent
                seen.append(
                    (Path(scan_dir), sorted(p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()))
                )
            return list(found), []

        return run

    monkeypatch.setattr(scanners, "RUNNERS", {"trivy": make(trivy), "checkov": make(checkov)})


@pytest.fixture
def estate(tmp_path):
    """A root that calls one local module twice, from outside its own directory."""
    return write(
        tmp_path / "repo",
        {
            "envs/prod/main.tf": ROOT + 'resource "aws_instance" "app" {\n  vpc_security_group_ids = [module.a.sg]\n}\n'
            'module "a" {\n  source = "../../modules/web"\n  name = "a"\n}\n'
            'module "b" {\n  source = "../../modules/web"\n  name = "b"\n}\n',
            "modules/web/main.tf": WEB,
            "modules/web/.checkov.yaml": "external-checks-git: [https://example.invalid/x]\n",
            "envs/dev/main.tf": ROOT + 'resource "aws_s3_bucket" "other" {}\n',
        },
    )


def test_the_copy_holds_exactly_what_the_graph_read(estate, monkeypatch):
    seen = []
    runners(monkeypatch, seen=seen)
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    assert not s.failed
    scan_dir, files = seen[0]
    assert files == ["envs/prod/main.tf", "modules/web/main.tf"]  # no dotfiles, no other root
    assert scan_dir.as_posix().endswith("target/envs/prod")  # the same layout: ../../modules/web still resolves
    assert not scan_dir.exists()  # removed afterwards


def test_a_module_finding_lands_in_every_instance_or_the_one_named(estate, monkeypatch):
    f = "../../modules/web/main.tf"
    runners(
        monkeypatch,
        trivy=[raw(file=f, line=8, resource="module.b", id="AWS-0107")],  # trivy names the call, not the resource
        checkov=[raw("checkov", file=f, line=3, resource="module.a.aws_security_group.web", id="CKV_AWS_24")],
    )
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    got = {(x.source, x.id, x.address, x.file, x.line) for x in s.findings}
    assert got == {
        ("trivy", "AWS-0107", "module.b.aws_security_group.web", "modules/web/main.tf", 8),
        ("checkov", "CKV_AWS_24", "module.a.aws_security_group.web", "modules/web/main.tf", 3),
    }
    runners(monkeypatch, trivy=[raw(file=f, line=6)])  # nothing names the instance: both of them
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    assert {x.address for x in s.findings} == {"module.a.aws_security_group.web", "module.b.aws_security_group.web"}


def test_lines_outside_a_resource_and_module_calls(estate, monkeypatch):
    runners(
        monkeypatch,
        trivy=[
            raw(file="../../modules/web/main.tf", line=1),  # the variable block: no resource
            raw(file="../../modules/web/main.tf", line=12, id="X-2"),  # the output after the resource
            raw(file="main.tf", line=5, id="CKV_TF_1"),  # inside `module "a"`
        ],
    )
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    assert sorted((x.id, x.address) for x in s.findings) == [("CKV_TF_1", "module.a"), ("X-1", ""), ("X-2", "")]


def test_checkov_secrets_are_redacted_and_text_is_one_line(estate, monkeypatch):
    runners(
        monkeypatch,
        checkov=[
            raw(
                "checkov",
                id="CKV_SECRET_6",
                resource="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
                file="main.tf",
                line=2,
                title="line\x1b]52;c;AAAA\x07\nbreak",
                url="javascript:alert(1)",
            )
        ],
    )
    (f,) = scanners.scan(graph.build(estate, "envs/prod"), estate).findings
    assert f.resource == scanners.REDACTED_SECRET and f.address == "aws_instance.app"
    assert "\x1b" not in f.title and "\n" not in f.title and f.url == ""


@pytest.mark.parametrize("bad", ["../../../../../../etc/passwd", "/etc/passwd", "git::https://x/y//main.tf"])
def test_a_finding_from_outside_the_copy_fails_that_scanner(estate, monkeypatch, bad):
    runners(monkeypatch, trivy=[raw(file=bad)], checkov=[raw("checkov", file="main.tf", line=2)])
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    assert s.failed == ["trivy"] and "outside the scanned copy" in s.status["trivy"]["error"]
    assert [x.source for x in s.findings] == ["checkov"]  # the other scanner's results stand


@pytest.mark.parametrize(
    "source",
    ['"/etc/terraform"', '"../../../../outside"', '"git::file:///tmp/repo"', "var.where", '"~/mods/x"'],
)
def test_a_module_source_that_leaves_the_folder_stops_the_scan(tmp_path, monkeypatch, source):
    repo = write(tmp_path / "repo", {"main.tf": ROOT + f'module "m" {{\n  source = {source}\n}}\n'})
    seen = []
    runners(monkeypatch, seen=seen)
    s = scanners.scan(graph.build(repo, "."), repo)
    assert s.failed == ["trivy", "checkov"] and not seen
    assert "outside the folder" in s.status["trivy"]["error"]


def test_another_folder_with_with_is_staged_beside_it(tmp_path, monkeypatch):
    repo = write(tmp_path / "platform", {"main.tf": ROOT + 'module "dns" {\n  source = "../shared/dns"\n}\n'})
    shared = write(tmp_path / "shared", {"dns/main.tf": 'resource "aws_route53_zone" "z" {}\n'})
    seen = []
    runners(monkeypatch, trivy=[raw(file="../shared/dns/main.tf", line=1)], seen=seen)
    assert scanners.scan(graph.build(repo, "."), repo).failed == ["trivy", "checkov"]  # without --with: refused
    seen.clear()
    s = scanners.scan(graph.build(repo, ".", [shared]), repo, [shared])
    assert seen[0][1] == ["platform/main.tf", "shared/dns/main.tf"]
    assert [(x.address, x.file) for x in s.findings] == [("module.dns.aws_route53_zone.z", "shared:dns/main.tf")]


def test_opentofu_files_are_scanned_under_their_own_name(tmp_path, monkeypatch):
    repo = write(tmp_path / "repo", {"main.tofu": ROOT + 'resource "aws_s3_bucket" "b" {}\n'})
    seen = []
    runners(monkeypatch, trivy=[raw(file="main.tofu.tf", line=2)], seen=seen)
    s = scanners.scan(graph.build(repo, "."), repo)
    assert seen[0][1] == ["main.tofu.tf"]
    assert [(x.address, x.file) for x in s.findings] == [("aws_s3_bucket.b", "main.tofu")]


def test_trivy_names_a_downloaded_module_after_its_source(tmp_path, monkeypatch):
    repo = write(
        tmp_path / "repo",
        {
            "main.tf": ROOT + 'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n',
            ".terraform/modules/modules.json": '{"Modules":[{"Key":"vpc","Source":"x","Dir":".terraform/modules/vpc"}]}',
            ".terraform/modules/vpc/main.tf": '\nresource "aws_vpc" "this" {\n  cidr_block = "10.0.0.0/16"\n}\n',
        },
    )
    runners(monkeypatch, trivy=[raw(file="terraform-aws-modules/vpc/aws/.terraform/modules/vpc/main.tf", line=3)])
    s = scanners.scan(graph.build(repo, "."), repo)
    assert [(x.address, x.file) for x in s.findings] == [("module.vpc.aws_vpc.this", ".terraform/modules/vpc/main.tf")]


def test_a_downloaded_module_index_pointing_away_is_refused(tmp_path, monkeypatch):
    repo = write(
        tmp_path / "repo",
        {"main.tf": ROOT, ".terraform/modules/modules.json": '{"Modules":[{"Key":"x","Dir":"/etc"}]}'},
    )
    s = scanners.scan(graph.build(repo, "."), repo)
    assert s.failed == ["trivy", "checkov"] and "modules.json" in s.status["checkov"]["error"]


def test_trivy_log_lines():
    lines = [
        '2026 ERROR [misconfig] Falling back to embedded checks err="x"',
        '2026 ERROR [terraform parser] Error parsing file file_path="bad.tf" cause="secret text"',
        "2026 ERROR [terraform evaluator] Failed to load module. Maybe try 'terraform init'? module=\"vpc\"",
        '2026 ERROR [rego] something broke path="q"',
        "2026 INFO all fine",
    ]
    unparsed, modules, errors = scanners.trivy_log("\n".join(lines))
    assert unparsed == ["bad.tf"]
    assert modules == ["[terraform evaluator] Failed to load module. Maybe try 'terraform init'?"]
    assert errors == ["[rego] something broke"]


def test_a_missing_scanner_is_a_failure_not_an_empty_list(estate, monkeypatch):
    monkeypatch.setattr(scanners, "RUNNERS", {"trivy": scanners.run_trivy, "checkov": scanners.run_checkov})
    monkeypatch.setenv("PATH", str(estate))  # neither is on it
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    assert s.failed == ["trivy", "checkov"] and "isn't installed" in s.status["trivy"]["error"]
    monkeypatch.setattr(scanners, "RUNNERS", {"trivy": lambda d, w: ([], []), "checkov": scanners.run_checkov})
    with pytest.raises(SystemExit) as e:
        cli.main([str(estate), "--root", "envs/prod", "--no-diagram"])
    assert e.value.code == cli.EXIT_INCOMPLETE


def test_scanner_output_is_bounded(tmp_path):
    p = sandbox.run_bounded(
        ["/bin/sh", "-c", "yes | head -c 200000"], cwd=str(tmp_path), env=None, timeout=30, limit=4096
    )
    assert p.too_large and len(p.stdout) <= 4096


def test_findings_on_the_diagram(estate, monkeypatch):
    runners(
        monkeypatch,
        trivy=[raw(file="../../modules/web/main.tf", line=6, resource="module.a"), raw(file="main.tf", line=1, id="P")],
        checkov=[raw("checkov", file="main.tf", line=2, severity=None, url="https://docs.example/x")],
    )
    g = graph.build(estate, "envs/prod")
    s = scanners.scan(g, estate)
    m = arch.build(g, s.findings)
    app = next(c for c in m.components if c.id == "aws_instance.app")
    # the security group isn't drawn: its finding goes on the instance that uses it
    assert sorted(f["id"] for f in app.findings) == ["X-1", "X-1"]
    assert app.badges[0].text == "2 findings, worst high" and app.badges[0].risk
    assert [f["id"] for f in m.loose] == ["P"]  # the provider block
    page = diagram.render(m, "repo/envs/prod", scanned=True)
    assert '"scanned": true' in page and "https://docs.example/x" in page


def test_the_cli_reports_and_writes_findings(estate, monkeypatch, capsys):
    runners(monkeypatch, trivy=[raw(file="main.tf", line=2, id="AWS-0028")])
    out = estate / "g.json"
    with pytest.raises(SystemExit) as e:
        cli.main([str(estate), "--root", "envs/prod", "--no-diagram", "--graph-json", str(out)])
    assert e.value.code == cli.EXIT_OK
    text = capsys.readouterr().out
    assert "Vulnerabilities: 1 finding (trivy 9.9.9 1, checkov 9.9.9 0)" in text and "aws_instance.app" in text
    assert '"address": "aws_instance.app"' in out.read_text()


def test_resource_lines_after_a_blank_line(tmp_path):
    write(tmp_path, {"main.tf": 'provider "aws" {}\n\n\nresource "aws_vpc" "v" {}\n'})
    assert graph.build(tmp_path, ".").resources["aws_vpc.v"].line == 4


@pytest.mark.real_scanners
@pytest.mark.skipif(not (shutil.which("trivy") and shutil.which("checkov")), reason="trivy and checkov not installed")
def test_the_real_scanners(estate):
    s = scanners.scan(graph.build(estate, "envs/prod"), estate)
    assert not s.failed, s.status
    sg = {x.address for x in s.findings if x.source == "trivy" and "security_group" in x.address}
    assert sg == {"module.a.aws_security_group.web", "module.b.aws_security_group.web"}
    assert all(x.address for x in s.findings if x.source == "checkov")


def test_unquoted_labels_and_checkov_data_sources(tmp_path, monkeypatch):
    write(
        tmp_path,
        {
            "main.tf": ROOT
            + '\ndata aws_iam_policy_document "p" {\n  statement {}\n}\nmodule m {\n  source = "./m"\n}\n',
            "m/main.tf": "resource aws_s3_bucket b {}\n",
        },
    )
    g = graph.build(tmp_path, ".")
    assert (g.resources["data.aws_iam_policy_document.p"].line, g.resources["module.m.aws_s3_bucket.b"].line) == (3, 1)
    runners(
        monkeypatch,
        checkov=[raw("checkov", resource="aws_iam_policy_document.p", line=3), raw("checkov", line=6, id="CKV_TF_1")],
    )
    assert sorted((x.id, x.address) for x in scanners.scan(g, tmp_path).findings) == [
        ("CKV_TF_1", "module.m"),
        ("X-1", "data.aws_iam_policy_document.p"),
    ]


def test_a_rule_finding_reaches_the_instances_in_its_group(tmp_path, monkeypatch):
    write(
        tmp_path,
        {
            "main.tf": ROOT + 'resource "aws_security_group" "sg" {}\n'
            'resource "aws_security_group_rule" "r" {\n  security_group_id = aws_security_group.sg.id\n}\n'
            'resource "aws_instance" "i" {\n  vpc_security_group_ids = [aws_security_group.sg.id]\n}\n'
        },
    )
    runners(monkeypatch, trivy=[raw(line=4)])
    g = graph.build(tmp_path, ".")
    m = arch.build(g, scanners.scan(g, tmp_path).findings)
    assert [f["address"] for c in m.components for f in c.findings] == ["aws_security_group_rule.r"] and not m.loose
