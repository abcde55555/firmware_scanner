# Releasing Firmware Scanner

Releases are built from annotated Git tags and published by the
`.github/workflows/release.yml` GitHub Actions workflow.

## Release assets

Each release contains:

- a platform-independent wheel;
- a source distribution;
- standalone Linux, Windows, and macOS executables;
- `SHA256SUMS`;
- a machine-readable `release-manifest.json` with source commit, sizes, and
  digests.

The standalone application embeds the core analyzer, built-in rule packs,
CycloneDX/SPDX generators, and the main CLI. Optional integrations such as
radare2, Ghidra, and Android external tools remain optional and may require the
wheel/source installation.

## Cut a release

1. Update `pyproject.toml`, `CHANGELOG.md`, and release notes.
2. Run:

   ```bash
   pytest -q tests
   ruff check src tests
   python -m build
   python -m twine check dist/*
   ```

3. Merge the release branch into `main`.
4. Create and push an annotated tag:

   ```bash
   git tag -a vX.Y.Z -m "Firmware Scanner vX.Y.Z"
   git push origin main
   git push origin vX.Y.Z
   ```

The tag triggers the cross-platform build. The workflow creates a GitHub
Release if one does not exist, or uploads/replaces assets on an existing
release.

Before tagging, run a dry-run from the release branch:

```bash
gh workflow run release.yml \
  --ref codex/cross-platform-release-0.37 \
  -f release_tag=vX.Y.Z-dryrun \
  -f publish=false
```

This builds all three standalone executables and the Python package artifacts
without creating or modifying a GitHub Release.

## Local standalone build

Install PyInstaller and build the current platform:

```bash
python -m pip install -e . pyinstaller==6.22.3
pyinstaller --clean --noconfirm firmware_scanner.spec
./dist/firmware-scanner --help
./dist/firmware-scanner plugins
```

On Windows, run `dist/firmware-scanner.exe`.

## Signing status

- macOS executables are ad hoc signed by the release workflow but are not
  Developer ID signed or notarized.
- Windows executables are not Authenticode signed.

Users should verify `SHA256SUMS` after download. Production distributions that
need operating-system trust prompts suppressed should add the appropriate
Developer ID/notarization or Authenticode signing credentials to the release
workflow.
