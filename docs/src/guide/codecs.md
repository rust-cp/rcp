# Wire compression codecs

`-compress` keeps its LZ4 behavior and its version-5 handshake. `-compress.codec` names a
codec, `lz4`, `deflate` or `zstd`, and implies `-compress`. `-compress-codec` is the same
option, the spelling the first zstd change used. Naming two different codecs with the two
spellings is refused. The codec applies to payloads over `ssh://`, `rcp://` and `rcps://`,
including delta literals and streamed reads. Choosing between them is covered below
(**Pick `zstd` when...**).

zstd is in every build: this crate carries its own encoder and decoder, so no library and
no feature is needed. `cargo build --features system-zstd` swaps in the system libzstd as the
backend instead. Install the development/link library first (for example `libzstd-dev` on
Debian); the feature adds a small binding to its stable one-shot C API, with no new Cargo
packages, build script or downloads. The two backends make and read the same frames, so a
build with the feature and one without it compress to each other in both directions. The
test suite checks this. Cargo still needs registry metadata for the optional rustls
dependency to resolve the lockfile offline.

**The handshake.** Raw and LZ4 use protocol **5**, byte for byte as before. Any other codec
uses protocol **6**, naming itself with a tag in HELLO: zstd is **2**, deflate **3** (plus
its level). The serve must answer with the same tag. A serve that does not speak 6 refuses
it by version before it reads the target or creates a directory. A v6 tag it does not
answer is refused too. There is no silent downgrade, so use `-compress` for LZ4 with an
older peer. A payload's tag is never sent unless HELLO agreed to it.

The same prefix probe, 10% saving threshold and incompressible-block pause apply to every
codec. Unprofitable blocks go raw. Compressed payloads carry the original length and a
CRC-32 of the original bytes, and a claimed length beyond what the codec can produce is
refused before anything is allocated. The same codec also reads and writes `.tar.zst`
through `tar://`; see [Archives](../endpoints/tar.md).
