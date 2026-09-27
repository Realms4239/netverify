"""Entry point: `python -m server`.

Kept separate from `app.py` so that importing the tools for a test never
triggers transport setup, and so the module a human reads first is three lines
long.
"""

from .app import main

if __name__ == "__main__":
    main()
