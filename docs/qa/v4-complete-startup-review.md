# V4 complete startup and login review — 2026-10-27

## Findings and repairs

The supplied Codespaces logs established three different failures, which must
not be reported as a bad password:

1. Docker's default builder had missing parent snapshots. An independent
   docker-container Buildx build succeeded. The launcher now recognizes that
   specific error and uses an independent builder automatically; it does not
   prune images or volumes or hide other build failures.
2. A previous analysis container retained an older image. V4 refreshes that
   disposable container only after verifying its expected IPC mount. A source
   fingerprint now prevents an old tagged analysis image from surviving code
   changes unnoticed.
3. Demo provisioning then returned `YARA_VALIDATION_UNAVAILABLE`. The log only
   established a failed isolated computation, not its underlying exception.
   Landlock ABI 4 and YARA 4.5.4 were present. The sandbox unnecessarily loaded
   native PDF/DOCX engines for YARA requests; they are now loaded only for report
   jobs. A regression proves real YARA fixture validation works even when report
   imports fail. Child failures now record only operation, phase, exception type
   and errno, without evidence, rule source, passwords or exception messages.

The failed seeder left a partly initialized directory. The launcher now checks
YARA before provisioning and publishes a new demo directory only after all seed
operations complete. A recognized old partial synthetic directory is renamed to
a unique retained backup before replacement. Unknown directories are preserved.
Completed demo accounts, encryption keys and case manifests survive restart.

The owner subsequently ran `python run.py`, and `try_codespace.sh` explicitly
reported `instance/socify.db`. Those commands targeted the ordinary application
database; the synthetic accounts belonged to another database. The supported
path is now `.venv/bin/python run.py --demo --port 5001`. It uses one explicit
directory for the database, encryption keys and credentials, verifies all four
saved accounts with real CSRF-protected form login, and prints the matching
public Codespaces URL and an editor command for the accounts file.

V4 is now included in the existing CI push triggers. Full-project formatting
and type errors in the V4 OpenAPI generator were also corrected without changing
its generated API document.

## Acceptance evidence

- Final unit/integration/security regression: **867 passed**, 26 browser tests
  deselected by that suite's marker. The expected duplicate-ZIP-member warning
  comes from the capsule rejection fixture. See `v4-final-unit-integration.txt`.
- Browser acceptance: 26 tests, covering login, case selection and approval,
  related-case scope, role switching, tools, reports, keyboard/mobile layouts,
  Arabic/English, dark/light themes and accessibility. The final run is recorded
  separately in `v4-final-browser.txt`.
- The actual single-command launcher rebuilt the matching native analysis image,
  replaced its old container, recognized and preserved a copied legacy partial
  workspace, generated a complete new demo including real analysis and report,
  and served the site on a dedicated test port. Four independent HTTP sessions
  then logged in with the saved credentials and loaded `/api/auth/me` and `/cases`.
- Restart was checked against private-file fingerprints, not by publishing keys
  or passwords. Runtime credentials remain excluded from Git and Docker context.
- Ruff formatting and lint, mypy across 87 source files, Bash syntax, Bandit,
  OpenAPI regeneration and dependency audit passed. The dependency audit reported
  no known vulnerabilities in the pinned runtime requirements at review time.

## Kernel-specific check and limits

This managed host reports ENOSYS for Landlock, so native Docker acceptance alone
does not exercise the owner's Landlock path. A separate offline QEMU VM booted
the same Ubuntu Azure kernel release, `6.8.0-1064-azure`, using Ubuntu archive
packages verified against their package-index SHA-256 values. It reported ABI 4.

The VM used unprivileged analysis processes, a read-only root filesystem,
separate coordinator/analysis mount namespaces, dedicated hardened tmpfs scratch
mounts, no network device, and the real Landlock/seccomp boundary. Synthetic YARA
validation, full provisioning and four CSRF-protected account logins passed.
Software CPU emulation exceeded the normal report-rendering time budget on the
first full run; only the VM copy received a longer report timeout and CPU budget
for that check. Production/native limits were unchanged, and the native suite
and browser suite used their normal limits. No security filter was disabled.

These checks ran in verification environments, not inside the owner's live
Codespace. The owner must pull V4 and run the documented command there. A login
URL is printed after successful provisioning and credential verification; the
terminal must then show `Running on`. This is tested startup behavior, not a
claim that every external Docker or Codespaces service is universally available.
