# Negative SOW fixtures

`selftest.py` creates isolated temporary copies of the valid package and applies
one mutation per fixture. This avoids committing a second, potentially stale
copy of the authoritative policy and scope.

The fixtures cover candidate/commissioning state; candidate-003 identity and its
direct supersession of candidate-002; policy/scope ID mismatch; attempted reuse
of candidate-001 or candidate-002; reordering or alteration of the exact
candidate-001 then candidate-002 history; drift in candidate-002's subject,
tree, parent/SOW commit, triggering defect, diagnostic classification, review
scope, or any of its four typed non-evidence hashes; per-item mutation or removal,
reordering, unknown-entry injection, and false non-exhaustive marking for the
ordered four-defect invalidation set; false erasure of the two first-party
diagnostic observations; false promotion of wrapper validity, materialization,
bundle generation, evidence-commit creation, complete replay, external review,
audit-evidence acceptance, an external audit, or vendor contact; preservation
of candidate-001's exact partial-replay disposition;
subject boundary; auditor independence; specialist coverage; exact standards and
scope topics; finding-to-row mapping; exact severity/SLA and embargo semantics;
owner/approver requirements; complete issuance gates; release blockers; closure
records; public-report rules; deterministic Markdown reconciliation; machine-file
digest drift; malformed TOML; symlinked inputs and ancestors; unsafe roots; and
unexpected files. Every fixture must be rejected by `verify-sow.py` for its named
reason.
