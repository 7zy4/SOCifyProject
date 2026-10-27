# Codespaces build repair — 2026-10-27

The supplied complete log identifies the cause before the application starts:

```text
Err: https://dl.yarnpkg.com/debian stable InRelease
NO_PUBKEY 62D54FD4003F6525
E: The repository 'https://dl.yarnpkg.com/debian stable InRelease' is not signed.
```

Docker-in-Docker 4.1.3 runs `apt-get update`; APT also checks the unrelated Yarn repository inherited from the Python development image. Its missing signing key stops the Docker Feature with exit 100. Codespaces then starts its Alpine recovery container. Reinstalling Python packages inside that recovery container cannot repair the failing build.

The development configuration now uses a Dockerfile based on the same Python Bookworm image. It removes `/etc/apt/sources.list.d/yarn.list` before Features run. SOCify does not use Yarn. Other sources retain normal signature verification; no `trusted=yes`, insecure TLS or unauthenticated packages are used. The Feature is pinned to the observed 4.1.3 release; Docker Buildx remains enabled. Runtime report libraries are installed explicitly. Python dependencies are installed into `.venv`, preserving the existing database and keys.

`bash scripts/try_v4_demo.sh` prepares the analysis image/service, creates the isolated synthetic database only if its directory is absent, otherwise reuses it, and starts the demo. Existing incomplete directories are preserved and require a different directory name. It reports the accounts file path without printing passwords. This provides a repeatable V4 startup command after rebuilding the existing Codespace.

Validation:

- 46 targeted startup, proxy-login, environment-mode, bootstrap and key-contention tests passed.
- Ruff, Bash syntax checks, Dev Container JSON parsing and `git diff --check` passed.
- The unified launcher reused the existing synthetic database, started the app on a separate localhost port, returned HTTP 200 from `/health/ready`, and shut down using Ctrl+C. Account passwords and encryption keys were preserved.
- A Docker build on Python 3.12 / Debian Bookworm deliberately added the invalid Yarn source, ran the same removal layer, then completed the official Docker-in-Docker 4.1.3 installer. It verified that the Yarn source was absent and that Docker Engine/CLI 29.9.2 and Buildx 0.38.1 were installed. Proxy CA trust was supplied to APT/curl/Git/wget through a temporary build secret; TLS and package signatures stayed enabled.
- Pulling the full original MCR image in this managed runtime was blocked at its regional CDN redirect. The build verification therefore used the same Debian Bookworm/Python version on the official Python base, rather than claiming to rebuild the owner's exact Codespace. The repository's development Dockerfile continues to inherit the original MCR Python image and its `vscode` user.

The owner's Codespace itself is remote and must apply the new commit and rebuild; no account, evidence, key or volume needs deletion.

Reference: the same Yarn signing-key failure is documented in the upstream [Dev Containers issue 1605](https://github.com/devcontainers/features/issues/1605).
