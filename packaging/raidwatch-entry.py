"""PyInstaller entry point — absolute import (relative fails in onefile)."""

from raidwatch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
