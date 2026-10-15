# Security

kubectl-npmap only reads a cluster (`list` and discovery calls) and never
creates, updates or deletes anything. The web UI binds to localhost, answers
only to localhost host names, and has no authentication: do not expose it with
`--listen` on a shared network. Nothing leaves your machine except API calls
to your cluster and, with `--resolve-fqdn` or the web UI, DNS lookups of hosts
you ask about.

Release binaries are built by GitHub Actions from the tagged commit; verify
downloads against `checksums.txt` on the release page. Dependencies are
scanned with `govulncheck` on every push and kept current by Dependabot.

To report a vulnerability, use GitHub's private reporting on this repository
("Security" → "Report a vulnerability") rather than a public issue. You will
get a reply within a few days.
