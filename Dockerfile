# netverify - read-only MCP server for verifying ISP backbone device output.
#
# Two stages on purpose. The first installs the library with no dependencies at
# all and runs the full offline gate; the second adds the MCP SDK. That ordering
# is the security property made concrete: the verification core is provably
# importable and testable with nothing from the network installed, and only the
# protocol layer needs anything.
#
# Not pinned to a digest deliberately. Pinning to one would make this file
# silently rot the moment that image is rebuilt, and a build that fails loudly
# is better than one that fails to pull. For a supply chain you care about,
# replace `python:3.12-slim` with your digest and add a Trivy scan.

FROM python:3.12-slim AS base

# No build tools, no curl: nothing here compiles, and a compiler in the final
# image is attack surface with no offsetting benefit.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# --- stage 1: the library, dependency-free ---------------------------------
# The offline gates run here, before any network install, which proves the core
# genuinely needs nothing.
COPY netverify/ ./netverify/
COPY tests/ ./tests/
COPY evals/ ./evals/
COPY scripts/ ./scripts/

RUN python -m unittest discover -s tests -t . \
 && python evals/run_evals.py \
 && python scripts/check_upstream_parity.py --offline

# --- stage 2: add the MCP protocol layer ----------------------------------
COPY pyproject.toml README.md ./
COPY server/ ./server/

RUN pip install --no-cache-dir . \
 && pip install --no-cache-dir 'mcp==2.2.0'

# Run as a non-root user. The server holds no credential and opens no socket, so
# the blast radius of a compromise is already minimal; this is the last cheap
# layer rather than a meaningful defence.
RUN useradd --create-home --uid 10001 netverify
USER netverify

# Fail the container at start if the guards do not hold, rather than serving
# verdicts from an installation that cannot keep its own promises. This runs the
# same self-check the `self_check` tool exposes.
HEALTHCHECK --interval=60s --timeout=10s --retries=2 \
  CMD ["python", "-m", "netverify.cli", "self-check"]

# stdio is the transport: the client spawns this process and speaks MCP over its
# stdin/stdout. Nothing listens on a port, which is the point.
ENTRYPOINT ["python", "-m", "server"]
