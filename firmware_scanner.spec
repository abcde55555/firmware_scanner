# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, copy_metadata


datas = collect_data_files(
    "firmware_scanner",
    includes=["data/**/*"],
)
datas += copy_metadata("firmware-scanner")
datas += [
    ("README.md", "."),
    ("LICENSE", "."),
]

a = Analysis(
    ["scripts/standalone_entry.py"],
    pathex=["src"],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="firmware-scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
