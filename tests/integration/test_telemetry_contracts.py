from __future__ import annotations

from jsonschema import Draft202012Validator, FormatChecker

from edl import config
from edl.loader import load_json, load_mapping
from edl.telemetry import (
    discover_telemetry_sources,
    load_telemetry_source,
    matrix_is_current,
)
from edl.utils import sha256_file


def _sources() -> list[object]:
    return [load_telemetry_source(path) for path in discover_telemetry_sources(config.ROOT)]


def test_all_source_contracts_validate() -> None:
    schema = load_json(config.SCHEMAS_DIR / "telemetry-source.schema.json")
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    paths = discover_telemetry_sources(config.ROOT)
    assert len(paths) == 12

    for path in paths:
        source = load_telemetry_source(path)
        errors = sorted(validator.iter_errors(source.data), key=lambda error: list(error.path))
        assert not errors, f"{path}: {[error.message for error in errors]}"


def test_sources_with_samples_have_files() -> None:
    sources = _sources()
    with_samples = [source for source in sources if "sample_data" in source.data]
    assert len(with_samples) == 12
    for source in with_samples:
        sample = source.data.get("sample_data")
        assert isinstance(sample, dict)
        assert (config.ROOT / sample["path"]).exists()
        assert source.status in {"sampled", "ingested", "validated"}


def test_generated_matrix_is_current() -> None:
    sources = _sources()
    assert matrix_is_current(config.ROOT / "docs" / "telemetry-matrix.md", sources)


def test_sample_hashes_match_manifest() -> None:
    manifest = load_mapping(config.ROOT / "lab" / "datasets" / "manifest.yaml")
    datasets = manifest["datasets"]
    assert isinstance(datasets, list)
    for dataset in datasets:
        assert isinstance(dataset, dict)
        path = config.ROOT / dataset["path"]
        assert sha256_file(path) == dataset["sha256"]
