<div align="center">
<img src="https://raw.githubusercontent.com/harnumaix/temporal-hardening-solution-csprng/refs/heads/main/media/banner.png" alt="Banner" width="1250">
</div>

<br />

# ths-csprng

[![npm version](https://img.shields.io/npm/v/ths-csprng.svg)](https://www.npmjs.com/package/ths-csprng)
![Node.js](https://img.shields.io/badge/Node.js-%3E%3D24.7.0-green)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/harnumaix/temporal-hardening-solution-csprng/blob/main/LICENSE)
![Verify Status](https://github.com/harnumaix/temporal-hardening-solution-csprng/actions/workflows/verify.yml/badge.svg)
[![Socket Badge](https://badge.socket.dev/npm/package/ths-csprng/2.0.1)](https://badge.socket.dev/npm/package/ths-csprng/2.0.1)
[![Donate](https://img.shields.io/badge/@HarnumaIX-Donate-FF4D4D)](https://harnumaix.github.io/donate/)

<br />

Standard CSPRNGs assume that once a seed is generated, the history of how it was produced is irrelevant. In practice that assumption breaks down in documented, real-world ways — backdoored hardware RNGs, hypervisor entropy starvation, forked process state reuse, and OS-level DRBG compromises have all produced exploitable key material in production systems.

**THS (Temporal Hardening Solution)** is a multi-source CSPRNG wrapper built around the idea that no single entropy source should be trusted unconditionally. It derives randomness by observing a **sequential movie of system state** — CPU jitter, scheduler noise, GC pressure, and OS bytes — across many frames, mixing everything into a KMAC256 accumulator and optionally memory-hardening early frames with native `crypto.argon2id`. The result is a seed whose reconstruction requires an attacker to accurately simulate the full physical evolution of the machine across every frame, not just recover a single snapshot.

<br />

---

<br />

<div align="center">
<img src="https://raw.githubusercontent.com/harnumaix/temporal-hardening-solution-csprng/refs/heads/main/media/illustration_1.png" alt="Illustration 1" width="1250">
</div>

<br />

## The Real-World Threat Model

THS was designed around concrete, documented attack scenarios — not academic abstractions.

* **Backdoored hardware RNG (RDRAND / Dual_EC_DRBG).** Early Intel Ivy Bridge errata produced biased RDRAND output. The NSA-influenced Dual_EC_DRBG, standardised in [NIST SP 800-90A](https://csrc.nist.rip/publications/nistpubs/800-90A/SP800-90A.pdf) and shipped in RSA BSAFE and several TLS stacks, contained a deliberately chosen curve point that let its designer predict all future output from 32 bytes of observation. THS never forwards OS CSPRNG output directly — every byte is mixed through SHA3-512 with timing-derived entropy the DRBG cannot observe, and optionally stretched with argon2id.

* **VM / hypervisor entropy starvation.** Virtualised environments (AWS EC2, GCP, Azure, Docker) frequently boot with a near-empty kernel entropy pool because the guest OS has no access to physical hardware noise. The 2012 landmark paper [“Mining Your Ps and Qs”](https://factorable.net/paper.html) found tens of thousands of colliding RSA moduli from internet-wide key scans — a direct consequence of early-boot key generation in exactly these environments. THS compensates by harvesting CPU jitter, scheduler noise, GC pressure, and context-switch counters — sources that are genuinely unpredictable even in a VM, even when the kernel pool is nearly empty.

* **Forked process state reuse.** `fork()` duplicates the entire process address space, including any in-memory PRNG state. Two forked children starting from the same state produce identical byte streams. This famously affected OpenSSL in Debian via [CVE-2008-0166](https://www.cs.utexas.edu/~hovav/dist/debiankey.pdf) and has been rediscovered in Python, Ruby, and Go runtimes. THS re-seeds from fresh OS entropy at the start of **every** `random()` call, not just at initialisation. A forked child diverges immediately on its first call.

* **Forward-secrecy compromise.** After each `random()` call, the internal entropy storage is ratcheted forward with post-output frames generated *after* the output was committed. An adversary who captures the output cannot derive the next seed without also knowing scheduler events, OS reads, and hrtime values that had not yet occurred when the output was produced.

<br />

> 📖 **Documentation:** Full API breakdowns, edge cases, and advanced configurations are available at **[harnumaix.github.io/temporal-hardening-solution-csprng](https://harnumaix.github.io/temporal-hardening-solution-csprng/)**.

> 📦 **Full API context optimized for AI assistants and contributors** is available in [`llms-full.txt`](https://github.com/harnumaix/temporal-hardening-solution-csprng/blob/main/llms-full.txt).

<br />
<br />

---

<br />

## 🚀 Getting Started

```bash
npm install ths-csprng
```

> **Requires Node.js ≥ 24.7.0.**

<br />

---

## 🛠️ Quick Start

### Modern ESM (Node.js 24+, Bun)

```javascript
import THS from 'ths-csprng';

// Standard 256-bit secure random buffer (Level 2, 64 frames)
const entropy = await THS.random(32);

// Long-term master key with maximum hardening
const masterKey = await THS.random(64, {
    layers:          512,          // 512 sequential entropy frames
    harden:          3,            // Level 3: SHA3-512 + native argon2id
    mem:             65536,        // 64 MiB argon2id memory cost
    memoryH:         4,            // Apply argon2id to the first 4 frames
    trng:            true,         // Read directly from /dev/urandom
    sandwichMode:    true,         // Ratchet entropy storage forward post-output
    maxSandwichCount: 5,           // 5 post-output frames for forward secrecy
    label:           'myapp:master-key-v1',  // Domain-separation label
});
```

### CommonJS

```javascript
const { THS } = require('ths-csprng');

(async () => {
    const entropy = await THS.random(32);
    console.log(entropy.toString('hex'));
})();
```

<br />

---

## 💎 Hardening Levels

| Level | Mode | What it captures |
| :--- | :--- | :--- |
| **0** | **Benchmark only** | A single `process.hrtime.bigint()` sample. No OS reads, no entropy mixing. **Do not use in production.** |
| **1** | **Process metrics** | 17 process metrics: nanosecond hrtime, uptime, user/system CPU time, minor/major page faults, voluntary/involuntary context switches, V8 heap (used/total/external/arrayBuffers), RSS, `performance.now()`, the module-load anchor, wall-clock time, and the frame index. No OS reads. |
| **2** | **OS-mixed** *(recommended default)* | Level 1 metrics + 128 bytes of fresh OS entropy per frame, all hashed through SHA3-512. A second hrtime sample brackets the OS read, encoding syscall latency as entropy. Effective even in VMs with a stale kernel pool. |
| **3** | **Memory-hardened** | Level 2 + native `crypto.argon2id` on frames with index `< memoryH`. Each brute-force candidate requires `mem` KiB of RAM — GPU farms are bottlenecked by memory bandwidth, not compute. Gate with a small `memoryH` to limit latency impact. |

<br />

---

## ⚙️ Full Configuration Options

```javascript
const bytes = await THS.random(32, {
    // ── Core ────────────────────────────────────────────────────────────────
    layers:           64,          // Sequential entropy frames (2–32768)
    harden:           2,           // Snapshot hardening level (0–3)
    trng:             false,       // Read OS bytes from /dev/urandom directly
    buffer:           true,        // true → Buffer, false → Uint8Array

    // ── Forward Secrecy (Sandwich Mode) ─────────────────────────────────────
    sandwichMode:     true,        // Ratchet entropy storage with post-output frames
    maxSandwichCount: 3,           // Post-output frames to fold in (1–32768)

    // ── Argon2id (harden: 3 only) ────────────────────────────────────────────
    memoryH:          1,           // Frame indices [0, memoryH) receive argon2id
    mem:              16384,       // memoryCost in KiB (≥ 1024; default 16 MiB)
    passes:           3,           // timeCost / iteration count
    parallelism:      4,           // Degree of parallelism

    // ── Domain Separation ────────────────────────────────────────────────────
    label:            'THS-v2',    // KMAC256 personalisation string; change per key type
});
```

<br />

---

## 🧬 Advanced API

### Streaming Frames

`streamFrames` yields a continuous stream of hardened random frames without pre-committing to a fixed layer count. Each `yield` is an async suspension point that introduces real scheduler-driven jitter. The seed is ratcheted forward using both the emitted bytes *and* the hrtime at which the consumer resumed the generator — future output depends on when prior output was consumed.

The stream maintains its own seed, entirely separate from the cross-call entropy storage used by `random()`. Streaming and non-streaming uses cannot interfere with each other's forward-secrecy properties.

```javascript
import THS from 'ths-csprng';

let count = 0;
for await (const frame of THS.streamFrames(32, { harden: 2, label: 'myapp:session-tokens' })) {
    issueSessionToken(frame);
    if (++count >= 1000) break;  // generator runs indefinitely until stopped
}
```

`streamFrames` accepts the same entropy options as `random()` (`harden`, `memoryH`, `mem`, `passes`, `parallelism`, `trng`, `label`).

<br />

### `randomBytes` Drop-in Replacement

```javascript
import { randomBytes } from 'ths-csprng';

// Synchronous — WebCrypto getRandomValues, no THS overhead
const nonce = randomBytes(16);                         // → Uint8Array
const buf   = Buffer.from(randomBytes(16));            // safely wrapped

// Asynchronous — full THS sequential frame movie
const key   = await randomBytes(32, true);             // isHardenRNG=true
const key2  = await randomBytes(32, true, { harden: 3, mem: 32768 });
```

<br />

### Convenience Aliases

```javascript
await THS.rand(32);          // alias for THS.random()
await THS.rnd(32);           // alias for THS.random()
```

<br />

### Raw OS Entropy

```javascript
// Raw OS bytes with no THS mixing.
// Caller is responsible for zeroing the buffer when done.
const seed = await THS.raw(32);          // /dev/urandom (default: trng=true)
const seed2 = await THS.raw(32, false);  // crypto.randomBytes
```

<br />

### Synchronous WebCrypto Fill

```javascript
// Routes to window.crypto in browsers, node:crypto webcrypto in Node.js.
// No THS mixing — use when synchronous operation is required.
const u32 = THS.fillRandom(new Uint32Array(8));
const u8  = THS.fillRandom(new Uint8Array(32));
```

<br />

---

<br />

<div align="center">
<img src="https://raw.githubusercontent.com/harnumaix/temporal-hardening-solution-csprng/refs/heads/main/media/illustration_2.png" alt="Illustration 2" width="1250">
</div>

<br />

## 🔬 Design: The Sequential Movie

Entropy is derived by observing a **sequential movie of system state**, not a single snapshot:

```
seed ──► frame₀ ──► jitter ──► frame₁ ──► jitter ──► … ──► frameₙ
              ↓                     ↓                     ↓
          KMAC256 update per frame, interleaved with OS bytes
```

Each frame captures a unique time-slice of CPU jitter, scheduler noise, memory pressure, and GC artifacts. The frame loop is always sequential — never `Promise.all` — so the inter-frame timing spread is preserved as entropy. Concurrent scheduling would collapse the movie into a near-simultaneous snapshot, discarding the temporal structure entirely.

The cross-call **entropy storage** carries entropy across invocations. It is re-mixed with fresh OS bytes at the start of every `random()` call (preventing it from becoming a closed, self-referential loop) and ratcheted forward with post-output frames after each call (forward secrecy).

<br />

---

## Use Cases

| Use case | Recommended call |
| :--- | :--- |
| Nonces, IVs, UUIDs, session tokens | `randomBytes(len)` or `THS.fillRandom(arr)` — synchronous, zero overhead |
| Application-layer session keys | `THS.random(32)` — default options (Level 2, 64 frames) |
| Long-lived master keys / signing keys | `THS.random(64, { harden: 3, mem: 65536, layers: 256 })` |
| High-volume token streams | `THS.streamFrames(32)` — continuous, forward-secret, per-frame ratchet |
| Bootstrapping a separate DRBG | `THS.raw(64)` — raw OS bytes, caller manages mixing |
| Browser / WebCrypto contexts | `THS.fillRandom(new Uint8Array(n))` — routes to `window.crypto` |

<br />

---

> [!NOTE]
> 
> **Hardening Level 3** is computationally expensive by design. It is intended for long-term master keys or seeds where latency is acceptable and the threat model includes state-level adversaries. For high-frequency generation (UUIDs, nonces, IVs), use **Level 0** or **Level 1**, or the synchronous `randomBytes` / `fillRandom` path.

<br />

---

## 🛠️ Development & Verification

```bash
npm run check        # test + verify checksums
npm run build        # minify + generate docs + checksums
npm test
```

The project uses:

* `terser` for minification
* SHA-256 checksums for all built files
* [`@noble/hashes`](https://npmjs.com/package/@noble/hashes) for KMAC256 (audited, zero-dependency)
* Native `node:crypto` argon2id (Node.js 24+)
* Strict mode + comprehensive test suite

<br />

---

<br />

## ⭐ Contributor(s)

<a href="https://github.com/harnumaix/temporal-hardening-solution-csprng/graphs/contributors">
  <img alt="contributors" src="https://contrib.rocks/image?repo=harnumaix/temporal-hardening-solution-csprng"/>
</a>

<br />
<br />
<br />

## License

Licensed under the **Apache License, Version 2.0** — a permissive license with an explicit grant of patent rights and protection against contributor liability.

Copyright © 2026 Aries Harbinger. See the **[LICENSE](https://github.com/harnumaix/temporal-hardening-solution-csprng/blob/main/LICENSE)** file for full details.

<br />
<br />

## 🔗 Links

* [GitHub Repository](https://github.com/harnumaix/temporal-hardening-solution-csprng)
* [npm Package](https://www.npmjs.com/package/ths-csprng)
* Full AI Context **[llms-full.txt](https://github.com/harnumaix/temporal-hardening-solution-csprng/blob/main/llms-full.txt)**
* Full API Documentations **[harnumaix.github.io/temporal-hardening-solution-csprng](https://harnumaix.github.io/temporal-hardening-solution-csprng/)**

<br />
<br />
<br />
<br />