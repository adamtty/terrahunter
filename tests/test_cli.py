import pytest

from terrahunter import __version__, cli


def test_version(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"terrahunter {__version__}"


def test_says_it_is_being_rebuilt(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["some/folder"])
    assert e.value.code == 3  # not a result: nothing was analysed
    assert "being rebuilt" in capsys.readouterr().err
