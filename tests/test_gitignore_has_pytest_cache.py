from pathlib import Path


def test_gitignore_has_pytest_cache() -> None:
    gitignore = Path(__file__).resolve().parents[1] / ".gitignore"
    lines = [line.strip() for line in gitignore.read_text().splitlines()]
    assert ".pytest_cache/" in lines
