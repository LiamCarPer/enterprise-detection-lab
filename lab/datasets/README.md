# Lab Datasets

The lab uses synthetic or public, license-compatible data only. Raw datasets are never committed.

## Synthetic reference data

`lab/datasets/synthetic/` contains small reference events for the local lab:

- Entra ID sign-in
- Entra ID audit
- Sysmon
- Windows Security
- AWS CloudTrail

These events are generated for this repository. They use reserved documentation ranges, `example.test`, and fake identifiers. They contain no real users, hosts, accounts, keys, or production data.

## Manifest

`lab/datasets/manifest.yaml` records each dataset's source, path, license, provenance, and SHA-256. A file that is not in the manifest is not part of the lab.

## Adding data

1. Prefer public, licensed, or synthetic data.
2. Add a small, redacted sample to `lab/datasets/synthetic/` or a download script for larger data.
3. Record the source, license, provenance, and SHA-256 in `manifest.yaml`.
4. Never commit raw production data, PII, credentials, or malware.
5. Update the telemetry source's `sample_data` contract when the sample is used by a detection.

Large datasets belong in a script-driven download directory that is ignored by git. The manifest is the contract; the raw bytes are not.
