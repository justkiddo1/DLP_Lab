import json

from dlp.cli import main


def test_cli_finding_returns_1_and_valid_json(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("SSN: 123-45-6789\n", encoding="utf-8")
    code = main(["file", str(f), "-f", "json"])
    assert code == 1
    assert json.loads(capsys.readouterr().out)["total"] == 1


def test_cli_clean_returns_0(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("hello\n", encoding="utf-8")
    assert main(["file", str(f)]) == 0


def test_cli_missing_path_returns_2(tmp_path, capsys):
    assert main(["file", str(tmp_path / "nope")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_cli_writes_output_file(tmp_path):
    f = tmp_path / "a.txt"
    f.write_text("SSN: 123-45-6789\n", encoding="utf-8")
    out = tmp_path / "r.json"
    main(["file", str(f), "-f", "json", "-o", str(out)])
    assert json.loads(out.read_text(encoding="utf-8"))["total"] == 1