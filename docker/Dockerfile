# StegoScan with the full optional toolchain preinstalled.
#
# StegoScan itself needs nothing but Python. This image exists for the other
# half of the problem: binwalk, steghide, zsteg and friends drift between
# distributions and versions, so two examiners running "the same" scan on two
# machines can get different results. Pinning them here makes a scan
# reproducible across engagements.
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="stegoscan" \
      org.opencontainers.image.description="Steganography triage for CTF, pentest and forensic workflows" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        binwalk \
        foremost \
        steghide \
        exiftool \
        ent \
        imagemagick \
        ruby \
        ruby-dev \
        build-essential \
        ca-certificates \
    && gem install --no-document zsteg \
    # Build tooling is only needed for the zsteg native extension.
    && apt-get purge -y --auto-remove build-essential ruby-dev \
    && rm -rf /var/lib/apt/lists/*

# stegseek is not packaged in Debian; install the upstream release.
ARG STEGSEEK_VERSION=0.6
ADD https://github.com/RickdeJager/stegseek/releases/download/v${STEGSEEK_VERSION}/stegseek_${STEGSEEK_VERSION}-1.deb /tmp/stegseek.deb
RUN apt-get update \
    && apt-get install -y --no-install-recommends /tmp/stegseek.deb \
    && rm -f /tmp/stegseek.deb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/stegoscan
COPY stegoscan/ ./stegoscan/
COPY pyproject.toml README.md ./

# No pip install: the package has no dependencies, so the source tree is the
# installation. Keeps the image small and the provenance obvious.
ENV PYTHONPATH=/opt/stegoscan

# Evidence is mounted read-only; artifacts are written to the working directory.
#   docker run --rm -v "$PWD:/evidence:ro" -v "$PWD/out:/out" stegoscan /evidence/target.jpg -o /out
WORKDIR /out
VOLUME ["/evidence", "/out"]

# A non-root user, because nothing here needs privileges.
RUN useradd --create-home --uid 1000 analyst && chown analyst /out
USER analyst

ENTRYPOINT ["python3", "-m", "stegoscan"]
CMD ["--help"]
