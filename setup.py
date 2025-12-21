"""
Setup script for building macOS .app bundle.

Usage:
    pip install py2app
    python setup.py py2app
"""

from setuptools import setup

APP = ['run_3lock.py']
DATA_FILES = []
OPTIONS = {
    'argv_emulation': False,
    'iconfile': 'icon.icns',
    'plist': {
        'CFBundleName': '3Lock',
        'CFBundleDisplayName': '3Lock',
        'CFBundleIdentifier': 'dev.kalba.3lock',
        'CFBundleVersion': '0.1.0',
        'CFBundleShortVersionString': '0.1.0',
        'NSHumanReadableCopyright': '© 2025 Kalba Lab. MIT License.',
        'NSHighResolutionCapable': True,
    },
    'packages': ['threelock', 'cffi', 'argon2'],
}

setup(
    app=APP,
    data_files=DATA_FILES,
    options={'py2app': OPTIONS},
    setup_requires=['py2app'],
)