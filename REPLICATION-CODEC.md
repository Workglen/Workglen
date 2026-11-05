# Native replication codec

Workglen's two bincode call sites now use `src/replication_codec.rs`. This is a
small codec for the existing `Vec<Op>` replication log, not a general serializer.
The stored and transmitted bytes are unchanged. Current databases reopen and
existing replication log frames replay without conversion, a new version marker,
or an importer. redb storage, transaction atomicity, sequence handling, backups,
replication checksums and transport authentication remain unchanged.

## Byte format

All lengths/counts are unsigned 64-bit little-endian integers. A frame contains:

1. Operation count.
2. For each operation: key byte length, UTF-8 key bytes, one-byte option tag.
3. Tag 0 means delete; tag 1 is followed by value byte length and raw value bytes.

An empty frame is the eight zero bytes encoding an empty operation list. A
present zero-byte value differs from deletion. Unicode keys, NUL bytes, empty
keys, repeated operations and binary values retain their previous encoding.

The unchanged 24 MiB encoded transaction limit is shared with the replication
transport. Encoding checks the complete size before reserving memory. Decoding
checks all lengths, UTF-8, option tags, operation counts and exact frame exhaustion
before allocating decoded operations. Integer conversions and additions are
checked; allocation failures return errors. Invalid or oversized frames do not
change database contents, sequence or logs. Decoded operations have memory
overhead beyond the encoded frame size; 24 MiB is not a total memory limit.

## Dependency review and verification

This checkpoint removes only bincode 1.3.3: **189 to 188 external package
versions**, comprising 187 registry packages and the attributed mail-auth path
package. No package is added, upgraded or changed in checksum. See
`validation/0.8-native-bincode-inventory.json`.

The normal suite includes a manually specified legacy byte fixture, empty and
binary values, malformed lengths/tags/UTF-8, every truncation of that fixture,
trailing data, the exact 24 MiB boundary, oversize rollback, persisted log reopen
and replay. `tools/replication-codec-compat.rs` is a separate development oracle
against the previous checkpoint's pinned bincode 1.3.3. Its reproduction steps
are at the top of that file. It is not part of the current dependency graph.

Executed on Linux x86-64 with Rust 1.99.1: **152 offline locked Rust tests**,
release Clippy with warnings denied, release build and **119 loopback
mail/replication checks** passed. The old-codec oracle passed 10,000 generated
operation lists with identical bytes and bidirectional decoding, the exact
24 MiB boundary, and 123,184 truncation/mutation/trailing/random-frame acceptance
comparisons. Results are in `validation/0.8-native-bincode-*`. These are synthetic
local checks; neither live host nor Microsoft 365 was exercised or changed.

Rebuild with `bash install.sh build` as the normal build account. For a
disposable test installation, follow the M5 Mac/Ubuntu test-server stop, binary
replacement and restart instructions. Keep that test configuration, keys and
databases. This source checkpoint deploys nothing automatically and does not
update any current installation.
