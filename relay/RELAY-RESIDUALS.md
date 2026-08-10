# Relay residuals

The relay's standing limitations are now merged into the project's canonical residual
list: see `../docs/NAMED-RESIDUALS.md`, entries **R8** (per-mailbox budgets shared by
write_cap holders → one mailbox per pairing), **R9** (delete-on-pull is at-most-once →
sender retry-until-acked), and **R10** (the global byte cap is an availability boundary,
not a security one). This file is kept only as a pointer to avoid two sources of truth.
