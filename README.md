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

### OOB Read / Kernel Heap Exposure
Scanning `64 KB` starting at `base2` (and `3.2 MB` in the extended
variant) produced a dump containing:

| Offset | Value | Interpretation |
|---|---|---|
| `+0x4000` | `0x0000000200000002` | Header-like |
| `+0xC3A0` | `0xA9A9A9A200000000` | XNU kalloc poison |
| `+0xF270` | `0x3B3B3B3B3B3B3B0B` | XNU fill pattern |
| `+0x9140`…`+0xF2A8` | clusters at ~`0x4A0` stride | kalloc zone slab |
| multiple | `0xFFFFAD0000000000 / 0x000056FFFFFFFFFF` | PAC-tagged pointer pair |
| multiple | `0xFFFFFFFFFFD2xxxx` | guard/tag constant |

See [`logs/`](./logs/) for full dumps.

---

## What Is Confirmed vs. What Is Not

| Claim | Status |
|---|---|
| Adjacent IOSurface allocations (Δ = `0x4000`) exist | ✅ Confirmed |
| OOB Write across adjacency boundary | ✅ Confirmed |
| OOB Read past `base2` returns non-zero data | ✅ Confirmed |
| Returned data resembles XNU kernel heap (poison, stride, PAC) | ✅ Strong evidence |
| The leaked pointers are *current* kernel pointers usable for KASLR defeat | ⚠️ Not yet verified (KASLR slide not cross-checked) |
| This is a pure exploitation primitive on stock iOS | ❓ Tested only in `newjail`; behavior on stock iOS TBD |

---

## Repository Layout
