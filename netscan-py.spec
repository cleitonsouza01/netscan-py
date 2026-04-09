# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for netscan-py.
Build on Windows with: pyinstaller netscan-py.spec
Requires nmap installed and in PATH on the target machine.
"""

a = Analysis(
    ['netscan-py.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'litellm',
        'litellm.llms',
        'litellm.llms.gemini',
        'httpx',
        'dotenv',
        'tqdm',
        'rich',
        'rich.console',
        'rich.table',
        'rich.panel',
        'tiktoken',
        'tiktoken_ext',
        'tiktoken_ext.openai_public',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='netscan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    icon=None,
)
