# Reviewed fuzz dictionaries

These libFuzzer dictionaries were authored from public dcrypt v3 wire labels and
public standards terminology on 2026-08-12. They contain no external corpus
bytes, private input, crash, or independent-oracle material. They are reviewed
bootstrap hints only and do not establish campaign execution or provenance for
mutated outputs.

The authoritative selector assigns `framing.dict` to `ecies_semantic`,
`hybrid_decoders`, `hybrid_semantic`, and `stream_frames`. It assigns
`crypto_tokens.dict` to the other thirteen targets, including
`legacy_xchacha_migration`; that dictionary includes the migration mode and AAD
delimiter controls as well as the selected semantic framing/state tokens.

The smoke runner selects exactly one applicable hint file and stages a private
writable copy of the target's reviewed seeds. Never give cargo-fuzz a directory
under `fuzz/seeds` as its primary corpus: libFuzzer writes minimized/new inputs
there. Dictionaries guide mutation only; they do not make source seeds writable
or prove a campaign ran.
