# Security policy

## Reporting a vulnerability

Email **hello@localfirstlab.org**. If the report is sensitive, encrypt it to the release
signing key: https://localfirstlab.org/keyweave-release-key.asc, fingerprint
`D78D89413752779209479B9ACF5C8AB3DB4A56EB`.

Please do not open a public issue for an undisclosed vulnerability.

This is a small open-source project, not a company: there is no bug bounty, and response is
best effort by one maintainer. What you can expect: an acknowledgement, an honest assessment,
and credit in the release notes of the fix if you want it.

## Scope

The deployed instances at `keyweave.localfirstlab.org` and `relay.keyweave.localfirstlab.org`
are in scope for coordinated disclosure only: do not run denial-of-service tests against them,
and do not touch mailboxes that are not yours. A copy you host yourself is yours to test
however you please.

## What already carries a number

Keyweave documents its known limits as named residuals in
[docs/NAMED-RESIDUALS.md](docs/NAMED-RESIDUALS.md). A report that restates a residual (no
forward secrecy, relay traffic metadata, served-code trust, and so on) is not a new finding.
A report showing a residual is materially WORSE than documented very much is one.

## Supported versions

The latest release only. v0 has no backport channel.
