def test_reference_artifact_has_fixtures() -> None:
    from pathlib import Path

    assert Path("fixtures/positive.json").exists()
    assert Path("fixtures/negative.json").exists()
    assert Path("fixtures/benign.json").exists()
