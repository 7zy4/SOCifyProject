# V4 analysis image refresh

The owner's Codespaces log showed a successful isolated Buildx build and image
import, followed by `Existing development backend differs; inspect it before
replacement.` The existing named development container still used the preceding
image. Startup stopped before demo provisioning, explaining the absent
`instance/v4-codespace-login/accounts.json`.

V4 now opts into refreshing its disposable analysis container when the image ID
changes. The IPC bind source must still match the configured development path.
A different mount is refused before stopping or removing anything. A failed stop
also prevents removal. V3 retains its previous explicit replacement behavior.
No database, keys, credentials, image cache, or Docker volume is deleted.

Verification on 2026-10-27:

- 32 targeted tests passed: stale-image refresh, refusal without opt-in, foreign
  mount preservation, stop failure, Codespaces forwarded HTTPS/CSRF, and password
  integrity. Ruff and Bash syntax checks passed.
- Created a disposable real Docker container with an older analysis image and
  an isolated IPC path; ran the updated startup script against the new image.
  It replaced that container and exposed its analysis socket successfully.
- Provisioned a new temporary synthetic workspace against the real isolated
  service, including sample analysis and report generation. All four generated
  accounts completed CSRF-protected form login and authenticated `/api/auth/me`.
  Only disposable verification resources were cleaned up.

The owner's Codespace is separate from the test environment. To apply the repair,
pull V4 and rerun the demo launcher using the same directory and port. The image
already built successfully is reused. This verification does not claim that the
owner's remote server has already been restarted.
