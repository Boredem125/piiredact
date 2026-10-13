import doctest
from pathlib import Path

README = Path(__file__).parent.parent / "README.md"


def test_readme_examples_run():
    result = doctest.testfile(str(README), module_relative=False, encoding="utf-8")
    assert result.failed == 0
    assert result.attempted >= 8
