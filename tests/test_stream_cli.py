import io
import json
import subprocess
import sys

import pytest

from depii import Redactor
from depii.cli import EXIT_ERROR, EXIT_FOUND, EXIT_OK, main
from depii.stream import chunks, redact_lines, redact_stream

KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" * 6
    + "-----END RSA PRIVATE KEY-----\n"
)


class TestStream:
    def test_chunks_split_at_line_ends_and_lose_nothing(self):
        lines = [f"line {i}\n" for i in range(1000)]
        parts = list(chunks(lines, size=256))
        assert len(parts) > 10
        assert "".join(parts) == "".join(lines)
        assert all(part.endswith("\n") for part in parts)

    def test_private_key_is_not_cut_in_half(self):
        lines = ("x\n" * 40 + KEY + "y\n" * 80).splitlines(keepends=True)
        parts = list(chunks(lines, size=128))
        assert len(parts) > 1
        assert sum(KEY in part for part in parts) == 1
        out = "".join(r.text for r in redact_lines(lines, Redactor(), chunk_size=128))
        assert "MIIBOg" not in out and out.count("[SECRET]") == 1

    def test_unfinished_key_does_not_buffer_forever(self):
        lines = ["-----BEGIN PRIVATE KEY-----\n"] + ["AAAA\n"] * 1000
        assert len(list(chunks(lines, size=100))) > 5

    def test_redact_stream(self):
        source = io.StringIO("a jane@example.com\nb 203.0.113.9\r\nc\n" * 50)
        sink = io.StringIO()
        totals = redact_stream(source, sink, Redactor(), chunk_size=128)
        assert totals == {"EMAIL": 50, "IP_ADDRESS": 50}
        assert sink.getvalue() == "a [EMAIL]\nb [IP_ADDRESS]\r\nc\n" * 50


@pytest.fixture
def run(tmp_path, capsys):
    def invoke(*argv, text=None):
        args = list(argv)
        if text is not None:
            path = tmp_path / "in.txt"
            path.write_bytes(text.encode("utf-8"))
            args.insert(1, str(path))
        out = tmp_path / "out.txt"
        if args[0] == "redact":
            args += ["-o", str(out)]
        code = main(args)
        captured = capsys.readouterr()
        written = out.read_bytes().decode("utf-8") if out.exists() else ""
        return code, written, captured.out, captured.err

    return invoke


class TestCli:
    def test_redact_text_preserves_line_endings(self, run):
        code, written, _, _ = run("redact", text="a jane@example.com\r\nb é 203.0.113.9\n")
        assert code == EXIT_OK
        assert written == "a [EMAIL]\r\nb é [IP_ADDRESS]\n"

    def test_operators(self, run, monkeypatch):
        text = "card 4111 1111 1111 1111\n"
        assert run("redact", "--operator", "mask", "--keep-last", "4", text=text)[1] == (
            "card **** **** **** 1111\n"
        )
        assert run("redact", "--operator", "drop", text=text)[1] == "card \n"
        monkeypatch.setenv("DEPII_HASH_KEY", "k" * 32)
        hashed = run("redact", "--operator", "hash", text=text)[1]
        assert hashed.startswith("card [CREDIT_CARD:") and "4111" not in hashed

    def test_hash_without_key_fails(self, run, monkeypatch):
        monkeypatch.delenv("DEPII_HASH_KEY", raising=False)
        with pytest.raises(SystemExit, match="DEPII_HASH_KEY"):
            run("redact", "--operator", "hash", text="x\n")

    def test_filters(self, run):
        text = "jane@example.com 078-05-1120 2345 6789 0124\n"
        assert run("redact", "--entities", "email", text=text)[1] == (
            "[EMAIL] 078-05-1120 2345 6789 0124\n"
        )
        assert run("redact", "--exclude", "EMAIL", "--locales", "us", text=text)[1] == (
            "jane@example.com [US_SSN] 2345 6789 0124\n"
        )

    def test_report(self, run):
        _, _, _, err = run("redact", "--report", text="jane@example.com 203.0.113.9\n")
        assert json.loads(err) == {"EMAIL": 1, "IP_ADDRESS": 1}

    def test_jsonl(self, run):
        text = (
            '{"msg": "from jane@example.com", "password": "hunter2", "n": 1}\n'
            "\n"
            "not json jane@example.com\n"
        )
        code, written, _, _ = run("redact", "--format", "jsonl", text=text)
        lines = written.split("\n")
        assert code == EXIT_OK
        assert json.loads(lines[0]) == {"msg": "from [EMAIL]", "password": "[SECRET]", "n": 1}
        assert lines[1] == ""
        assert lines[2] == "not json [EMAIL]"

    def test_csv_uses_header_hints(self, run):
        text = 'id,email,phone,note\n1,jane@example.com,5550132,"hi, 203.0.113.9"\n'
        _, written, _, _ = run("redact", "--format", "csv", text=text)
        assert written == 'id,email,phone,note\n1,[EMAIL],[PHONE],"hi, [IP_ADDRESS]"\n'
        _, written, _, _ = run("redact", "--format", "csv", "--no-header", text=text)
        assert written.splitlines()[1] == '1,[EMAIL],5550132,"hi, [IP_ADDRESS]"'

    def test_scan_exit_codes_and_positions(self, run):
        code, _, out, err = run("scan", text="clean\nmail jane@example.com\n")
        assert code == EXIT_FOUND
        assert ":2:6: EMAIL (0.95)" in out and "jane" not in out
        assert "1 finding(s)" in err
        assert run("scan", text="nothing here\n")[0] == EXIT_OK

    def test_scan_json_and_show_values(self, run):
        _, _, out, _ = run("scan", "--json", "--show-values", text="x\n\nip 203.0.113.9\n")
        record = json.loads(out)
        assert (record["line"], record["column"], record["entity"], record["value"]) == (
            3, 4, "IP_ADDRESS", "203.0.113.9",
        )  # fmt: skip

    def test_entities_command(self, run):
        code, _, out, _ = run("entities", "--locales", "us")
        assert code == EXIT_OK
        assert "US_SSN" in out.split() and "IN_AADHAAR" not in out.split()

    def test_errors_return_2(self, run, tmp_path):
        assert run("scan", str(tmp_path / "missing.txt"))[0] == EXIT_ERROR
        assert run("scan", "--locales", "zz", text="x\n")[0] == EXIT_ERROR


def test_module_runs_as_a_pipe():
    done = subprocess.run(
        [sys.executable, "-m", "depii", "redact", "-"],
        input="é jane@example.com\r\n".encode(),
        capture_output=True,
        check=True,
    )
    assert done.stdout == "é [EMAIL]\r\n".encode()
