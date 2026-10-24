"""`terrahunter map <folder>`: stages 1-3 only (the connections and the diagram), no scanners and no attack paths;
`terrahunter hunt <folder>` is the full run, the same as `terrahunter <folder>`."""

import json

import pytest
from test_chains import BUCKETS, NET, ROLE, WILDCARD_S3, instance, sg

from terrahunter import cli, kb, scanners

EXPOSED = (
    NET
    + ROLE
    + BUCKETS
    + WILDCARD_S3
    + sg("web", 80)
    + instance("web", "pub", "web", "  iam_instance_profile = aws_iam_instance_profile.app.name\n")
)


def run(args, capsys) -> tuple[int, str]:
    with pytest.raises(SystemExit) as e:
        cli.main(args)
    return e.value.code, capsys.readouterr().out


def test_map_stops_after_the_diagram(tmp_path, monkeypatch, capsys):
    (tmp_path / "main.tf").write_text(EXPOSED)
    called = []
    monkeypatch.setattr(scanners, "scan", lambda *a, **k: called.append(a))
    out, page = tmp_path / "g.json", tmp_path / "d.html"
    code, text = run(["map", str(tmp_path), "--graph-json", str(out), "--diagram", str(page)], capsys)
    assert code == cli.EXIT_OK and not called
    assert "Connections in .:" in text and "Attack paths" not in text and "Vulnerabilities" not in text
    g = json.loads(out.read_text())["graphs"][0]
    assert g["edges"] and "attack_paths" not in g and "scan" not in g
    html = page.read_text()
    assert '"walked": false' in html and '"scanned": false' in html and '"chains": []' in html


@pytest.mark.parametrize("flag", [["--report", "r.md"], ["--fail-on", "high"], ["--no-scan"]])
def test_map_has_no_hunting_options(tmp_path, capsys, flag):
    (tmp_path / "main.tf").write_text(EXPOSED)
    with pytest.raises(SystemExit) as e:
        cli.main(["map", str(tmp_path), *flag])
    assert e.value.code == 2  # argparse: unrecognised argument
    assert "unrecognized arguments" in capsys.readouterr().err


def test_hunt_is_the_full_run(tmp_path, capsys):
    (tmp_path / "main.tf").write_text(EXPOSED)
    code, text = run(["hunt", str(tmp_path), "--no-diagram", "--fail-on", "critical"], capsys)
    assert code == cli.EXIT_PATHS and "Attack paths: 1" in text


def test_a_folder_called_map(tmp_path, monkeypatch, capsys):
    (tmp_path / "map").mkdir()
    (tmp_path / "map" / "main.tf").write_text(EXPOSED)
    monkeypatch.chdir(tmp_path)
    _, text = run(["map"], capsys)  # nothing after it: the folder, and the full run
    assert "Attack paths: 1" in text


def test_kb_points_at_another_bundle(tmp_path, capsys):
    (tmp_path / "main.tf").write_text(EXPOSED)
    try:
        code, _ = run(["map", str(tmp_path), "--kb", str(kb.PACKAGED)], capsys)  # the shipped one, by path
        assert code == cli.EXIT_OK
        with pytest.raises(SystemExit) as e:  # a folder with no dist/ bundle
            cli.main(["map", str(tmp_path), "--kb", str(tmp_path)])
        assert e.value.code == cli.EXIT_ERROR
        assert "can't read the knowledge base" in capsys.readouterr().err
    finally:
        kb.use(None)
