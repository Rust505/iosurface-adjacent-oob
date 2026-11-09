# iosurface-adjacent-oob
SurfHeist — Adjacent IOSurface OOB Write / Kernel Heap Exposure

# SurfHeist: Adjacent IOSurface OOB Write & Kernel Heap Exposure

> **Status**: 🔬 Research in progress — preliminary report filed with Apple,
> under coordinated disclosure embargo. Full PoC will be published after
> patch lands / embargo expires.

> **Severity (self-assessed)**: Local OOB Write → potential heap corruption;
> OOB Read → kernel heap layout disclosure.

---

## TL;DR

On iOS 27.1, within the
`newjail` environment), we demonstrate that two `IOSurface` objects of
16 KB each can be allocated at **adjacent virtual addresses with a fixed
delta of `0x4000` and no intervening guard page**. This allows:

1. An **Out-of-Bounds (OOB) Write** from surface A into the first 16 KB of
   surface B — confirmed by round-trip write/read of a known marker.
2. An **Out-of-Bounds Read** past surface B into pages containing
   **structured kernel-heap-like data** — confirmed by the presence of XNU
   `kalloc` poison patterns (`0xA9A9...`, `0x3B3B...`), regular `kalloc`
   stride (~`0x4A0`), and PAC-tagged pointer-like fields.

---

## Technical Details

### Setup
- 50 `IOSurface`s created with identical properties:
  `64×64`, `BytesPerElement=4`, `PixelFormat='BGRA'` (16 KB each).
- Base addresses collected via `IOSurfaceGetBaseAddress`.

### Adjacency discovery
A simple scan for pairs `(i, i+1)` with `bases[i+1] - bases[i] == 0x4000`
reliably found **adjacent pairs without guard pages** on the tested
configuration.

### OOB Write
Iterating `offset` from `0x4000` to `0x8000`, writing `0x41414141` to
`base1 + offset` and verifying by reading `base2`. Confirmed hit at
`offset == 0x4000`:
