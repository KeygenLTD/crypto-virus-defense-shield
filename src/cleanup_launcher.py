"""PyInstaller entry point for the elevated emergency-cleanup utility."""

from src.cvds.cleanup import main

if __name__ == "__main__":
    raise SystemExit(main())
