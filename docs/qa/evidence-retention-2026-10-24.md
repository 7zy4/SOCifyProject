# Retained evidence content

New user-supplied raw logs, IoCs and text training artifacts now persist their original UTF-8 content encrypted with the configured credential encryption key in a separate immutable table. Metadata responses and reports never include the ciphertext. Schema startup adds the table and triggers without replacing old case data.

The scoped content endpoint verifies authenticated decryption and SHA-256 before returning a forced attachment with no-store and nosniff headers. It records the download in case history and the security audit. Neither a decryption failure nor a digest mismatch returns content. The UI exposes the download only when retained content exists.

Regression coverage includes encrypted storage, API redaction, byte-identical download after closure, immutable-content update/delete rejection, other-trainee denial, integrity failures, and persistence after recreating the application against the same database. Chromium downloads the retained fixture and verifies its bytes.

Previously submitted content cannot be reconstructed from its hash. Old references and event-linked evidence explicitly return `EVIDENCE_CONTENT_UNAVAILABLE` from this content endpoint; events keep their existing authorized raw source route. Historical contaminated links and comprehensive custody acceptance remain open, so F04-R07 is not marked PASS.

The new table is covered by the same database backup procedure; the configured encryption key must be retained separately to decrypt restored content. No key or original evidence content is written to the audit log.

REA was actually rerun after the UI update. See [the retained analysis and limitations](../research/rea-review-2026-10-24.md).
