# Negative SOW fixtures

`selftest.py` creates isolated temporary copies of the valid package and applies
one mutation per fixture. This avoids committing a second, potentially stale
copy of the authoritative policy and scope.

The fixtures cover candidate/commissioning state; candidate-002 identity;
policy/scope ID mismatch; attempted reuse of superseded candidate-001; false
erasure of the partial independent replay observations; false claims of completed
required replay, external review, or acceptable audit evidence; the exact
invalidated-after-partial-independent-replay-before-acceptance disposition;
subject boundary; auditor independence; specialist coverage; exact standards and
scope topics; finding-to-row mapping; exact severity/SLA and embargo semantics;
owner/approver requirements; complete issuance gates; release blockers; closure
records; public-report rules; deterministic Markdown reconciliation; machine-file
digest drift; malformed TOML; symlinked inputs and ancestors; unsafe roots; and
unexpected files. Every fixture must be rejected by `verify-sow.py` for its named
reason.
