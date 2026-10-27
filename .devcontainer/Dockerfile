FROM mcr.microsoft.com/devcontainers/python:1-3.12-bookworm

ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Yarn is not used by this Python project. The inherited Yarn APT repository
# has a missing signing key and causes the Docker Feature's apt-get update to
# fail with NO_PUBKEY 62D54FD4003F6525. Remove this optional source before Features.
# Keep normal APT signature verification enabled for every remaining source.
RUN rm -f /etc/apt/sources.list.d/yarn.list \
    && apt-get -o Acquire::Retries=3 update \
    && apt-get install --yes --no-install-recommends \
       libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libseccomp2 \
    && rm -rf /var/lib/apt/lists/*
