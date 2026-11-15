FROM mcr.microsoft.com/devcontainers/python:3.15-bookworm@sha256:043d2843b67306fad755de26cbf3effaf680109268839c152fdb767d77c966d9

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
