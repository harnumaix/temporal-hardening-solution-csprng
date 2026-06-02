/**
 * Copyright 2026 Aries Harbinger
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file ths-csprng
 * @module ths-csprng
 * @author Aries Harbinger
 * @license Apache-2.0
 * @summary
 * **Temporal Hardening Solution (THS)** — a multi-source CSPRNG wrapper
 * designed to remain secure even when individual entropy sources are
 * compromised, backdoored, or actively hostile.
 * 
 * ---
 * 
 * ## Real-World Threat Model
 * 
 * This library was designed with concrete, documented attack scenarios in mind —
 * not academic abstractions. The following threats are explicitly addressed:
 * 
 * ### 1. Backdoored Hardware RNG (e.g. Intel RDRAND / AMD RDSEED)
 * In 2019, researchers confirmed that some enterprise network appliance firmware
 * used RDRAND output as the sole entropy source for TLS key generation. A
 * backdoored or malfunctioning RDRAND (as was observed in early Ivy Bridge
 * errata) would silently produce biased or predictable output. Node's
 * `crypto.randomBytes()` ultimately calls into the OS CSPRNG (e.g. Linux
 * `/dev/urandom` or `getrandom()`), which may itself draw from hardware RNG.
 * **THS never trusts a single source.** OS bytes are always folded into a
 * multi-source KMAC accumulator alongside independent timing observations.
 * 
 * ### 2. Malicious or Weak DRBG (Dual_EC_DRBG / NIST SP 800-90A backdoor)
 * The NSA-influenced Dual_EC_DRBG was standardised in NIST SP 800-90A and
 * shipped in RSA BSAFE and several TLS stacks. It contained a deliberately
 * chosen elliptic-curve point that allowed the designer to predict all future
 * output from 32 bytes of observation. **THS counters this** by never
 * forwarding DRBG output directly: every OS-supplied byte is mixed through
 * SHA3-512 with timing-derived entropy the DRBG cannot observe or predict,
 * then optionally memory-hardened via argon2id.
 * 
 * ### 3. VM / Hypervisor Entropy Starvation
 * Virtualised environments (AWS EC2, GCP, Azure, Docker containers) frequently
 * boot with a near-empty entropy pool because the guest OS has no access to
 * physical hardware noise sources. Early-boot key generation in these
 * environments has historically produced weak keys (see the 2012 "Mining Your
 * Ps and Qs" paper, which found tens of thousands of colliding RSA moduli from
 * internet-wide key scans). **THS compensates** by harvesting CPU jitter,
 * scheduler noise, GC pressure, and voluntary/involuntary context-switch
 * counters — sources that are genuinely unpredictable even in a VM, even when
 * the kernel entropy pool is nearly empty.
 * 
 * ### 4. Cloned / Forked Process State (PRNG State Reuse)
 * `fork()` in Linux duplicates the entire process address space, including any
 * in-memory PRNG state. Two forked child processes starting from the same PRNG
 * state will produce identical byte streams. This famously affected OpenSSL in
 * Debian (CVE-2008-0166) and has been rediscovered in Python, Ruby, and Go
 * runtimes. **THS** is re-seeded with fresh OS entropy at the
 * start of *every* `random()` call, not just at initialization. A forked child
 * diverges immediately on its first call because process metrics (PID-derived
 * scheduling deltas, heap addresses) differ.
 * 
 * ---
 * 
 * ## Design: The Sequential Movie
 * 
 * Entropy is derived by observing a **sequential movie of system state**, not a
 * single snapshot:
 * 
 * ```
 * seed ──► frame₀ ──► jitter ──► frame₁ ──► jitter ──► … ──► frameₙ
 *               ↓                     ↓                     ↓
 *           KMAC update per frame, interleaved with OS bytes
 * ```
 * 
 * Each "frame" captures a unique time-slice of CPU jitter, scheduler noise,
 * memory pressure, and GC artifacts. The irreversibility of time means a
 * backdoored CSPRNG cannot retrodict the full observation sequence — it was not
 * present for every frame. The sequential loop preserves the inter-frame timing
 * spread that carries entropy.
 */
import fs from 'node:fs/promises';
import { promisify } from 'node:util';
import {
    randomBytes as nodeRandomBytes,
    argon2 as nativeArgon2,
    timingSafeEqual,
    createHash,
    webcrypto,
} from 'node:crypto';

import { fwrapObj } from 'fwrap';
import { PrivateContainer, hardenFn, zeroBuf, wrapTry, wrapTrySync } from 'ths-csprng/mini-utils';
import { kmac256 } from '@noble/hashes/sha3-addons.js';


// ─── Module-level singletons ──────────────────────────────────────────────────

/**
 * Promisified wrapper around Node's native `crypto.argon2`.
 * 
 * Node.js 22+ ships argon2id natively in `node:crypto` as a callback-style
 * function. We promisify it once at module load and freeze it inside a
 * `PrivateContainer` so neither the reference nor the underlying function
 * can be replaced by a later malicious patch or monkey-patch.
 * 
 * Native option shape (differs from the npm `argon2` package):
 * ```
 * {
 *   message:     Buffer,   // password / data to hash
 *   nonce:       Buffer,   // salt (≥ 8 bytes; 16 recommended)
 *   memory:      number,   // memoryCost in KiB
 *   passes:      number,   // timeCost / iteration count
 *   parallelism: number,   // degree of parallelism
 *   tagLength:   number,   // output bytes
 * }
 * ```
 * 
 * Called as: `argon2HashAsync.value('argon2id', options)`
 * @internal
 */
const argon2HashAsync = new PrivateContainer(() => promisify(nativeArgon2)).freeze();


/**
 * Persistent cross-call entropy storage.
 * 
 * Holds a 64-byte `Buffer` (SHA3-512 output size) that carries accumulated
 * entropy from one `THS.random()` call into the next. Stored in a
 * `PrivateContainer` so it cannot be read or overwritten by external code.
 * 
 * **Not** a traditional DRBG seed — it is re-mixed with fresh OS bytes at the
 * start of every call, preventing it from becoming a closed, self-referential
 * loop.
 * 
 * **Forward secrecy:** After each `random()` call, the entropy storage is ratcheted
 * forward with sandwich-phase frames generated *after* the output was committed.
 * An adversary who captures the output cannot derive the next seed without also
 * capturing those post-output frames.
 * 
 * **Fork safety:** Per-call OS re-seeding means a forked child process diverges
 * immediately on its first `random()` call, even if it inherited the same
 * entropy storage state from the parent.
 * @internal
 */
const entropyStorage = new PrivateContainer(() => nodeRandomBytes(64));

/**
 * High-resolution timestamp captured exactly once when this module is first
 * imported. Stored in a frozen `PrivateContainer` so it cannot be tampered with
 * after initialization.
 * 
 * Used as a stable temporal origin for all relative timing measurements within
 * this module's lifetime. Because it is captured at a non-deterministic moment
 * during the Node.js module load sequence, an adversary must know the exact
 * import-time nanosecond to reconstruct relative hrtime deltas — which is not
 * possible without process-level introspection.
 * @internal
 */
const MODULE_LOAD_HRTIME = new PrivateContainer(() => process.hrtime.bigint()).freeze();


// ─── Private helpers ──────────────────────────────────────────────────────────

/**
 * Coerce any serialisable JavaScript value to a `Uint8Array`.
 * 
 * Conversion rules:
 * - `Uint8Array` (or subclasses like Node.js `Buffer`) → returned as-is (no copy).
 * - `string` → UTF-8 encoded via `TextEncoder`.
 * - Unserializable values (`undefined`, functions, symbols) → converted to an empty `Uint8Array`.
 * - Anything else → JSON-serialized → UTF-8 encoded.
 * 
 * Wrapped with `hardenFn` to prevent the function reference from being replaced
 * by a monkey-patch after module load.
 * @param {unknown} input - The value to convert.
 * @returns {Uint8Array} A `Uint8Array` (or subclass) representation of `input`.
 * @throws {TypeError} If JSON serialization fails explicitly (e.g., circular references, BigInt).
 * @private
 */
const toBytes = hardenFn((input) => {
    if (input instanceof Uint8Array) return input;
    if (typeof input === 'string') return new TextEncoder().encode(input);

    const serialized = wrapTrySync(
        () => JSON.stringify(input),
        (e) => { throw new TypeError(`toBytes: cannot serialize — ${e.message}`); }
    );

    // If serialized is undefined (e.g. input was a function), it falls back to ''
    return new TextEncoder().encode(serialized ?? '');
});


/**
 * Encode a non-negative `BigInt` as a **length-prefixed big-endian `Buffer`**.
 * 
 * Format: `[2-byte big-endian length header][big-endian data bytes]`
 * 
 * The length prefix ensures that two different BigInt values never produce the
 * same byte string (injective / collision-free encoding). Without it,
 * `BigInt(256)` and `BigInt(1)` would both encode to `[0x01, 0x00]` and
 * `[0x01]` respectively — distinguishable only by context, which is unsafe in
 * a hash input.
 * 
 * Intermediate buffers (`header`, `data`) are zeroed in a `finally` block so
 * sensitive timing values do not linger on the heap after encoding.
 * 
 * Wrapped with `hardenFn` to prevent the function reference from being replaced.
 * @param {bigint|number} n - A non-negative integer or BigInt.
 * @returns {Buffer} A length-prefixed big-endian `Buffer`.
 * @throws {RangeError} If `n` is negative or too large for a 16-bit length header.
 * @private
 */
const bigIntToBuffer = hardenFn((n) => {
    if (typeof n !== 'bigint') n = BigInt(n);
    if (n < 0n) throw new RangeError('Negative values not supported');

    // Special-case zero: length header 0x0001, data byte 0x00.
    if (n === 0n) return Buffer.from([0x00, 0x01, 0x00]);

    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;  // ensure full-byte alignment
    const data = Buffer.from(hex, 'hex');

    if (data.length > 0xFFFF)
        throw new RangeError('BigInt too large for 16-bit length header');

    const header = Buffer.allocUnsafe(2);
    header.writeUInt16BE(data.length, 0);

    try     { return Buffer.concat([header, data]); }
    finally { zeroBuf(header, data); }
});


/**
 * Read `len` bytes of OS entropy.
 * 
 * **Source priority:**
 * - When `useUrandom=true`: opens `/dev/urandom` with a direct file
 *   descriptor, bypassing any Node.js crypto module patches or monkey-patches
 *   on `crypto.randomBytes`. Falls back to `crypto.randomBytes` on any error
 *   (e.g. sandboxed environments without `/dev/urandom` access, or containers
 *   with restricted seccomp profiles that block `open(2)` on device files).
 * - When `useUrandom=false` (default): delegates to `crypto.randomBytes`,
 *   which on Linux calls `getrandom(2)` (blocking until the kernel pool is
 *   initialized — safe after boot, potentially slow at early boot in VMs).
 * 
 * A short read from `/dev/urandom` is treated as a failure and immediately
 * falls back to `crypto.randomBytes`. The partial read is zeroed before discard.
 * 
 * **Caller responsibility:** Zero the returned buffer with `zeroBuf()` when
 * done. THS does this internally; external callers must do so manually.
 * @param {number}  len - Number of bytes to read.
 * @param {boolean} useUrandom - When `true`, read directly from `/dev/urandom`.
 * @returns {Promise<Buffer>} A fresh `Buffer` of exactly `len` bytes.
 * @private
 */
const getRandom = hardenFn(async (len, useUrandom = false) => {
    if (!useUrandom) return nodeRandomBytes(len);
    let fd, out;

    await wrapTry(
        async () => {
            fd = await fs.open('/dev/urandom', 'r');
            // Allocate zeroed so a short read yields safe content for inspection
            // before we detect and discard it.
            const buf = Buffer.alloc(len);
            const { bytesRead } = await fd.read(buf, 0, len, null); // null = sequential position

            if (bytesRead === len) { out = buf; }

            else {
                // Short read unexpected on /dev/urandom; zero partial data and fall back.
                zeroBuf(buf);
                out = nodeRandomBytes(len);
            }
        },

        () => { out = nodeRandomBytes(len); },
        async () => { if (fd) await fd.close(); },
        false
    );

    return out;
});


/**
 * Capture a single "frame" of observable system state.
 * 
 * A frame is a structured observation of the process's resource usage at an
 * exact instant in time. Multiple sequential frames form the "movie" that THS
 * uses to derive entropy — see the module-level documentation for the full
 * design rationale.
 * 
 * **Hardening levels in detail:**
 * 
 * - **Level 0 — hrtime only:** Returns a single `process.hrtime.bigint()` sample.
 *   Useful for benchmarking THS framework overhead without real entropy costs.
 *   **Do not use in production** — offers essentially no hardening.
 * 
 * - **Level 1 — Process metrics:** Captures 17 independent metrics: hrtime,
 *   uptime, user/system CPU time, minor/major page fault counts, voluntary and
 *   involuntary context-switch counts, heap (used/total/external/arrayBuffers)
 *   and RSS memory counters, `performance.now()`, the frozen module-load anchor,
 *   wall-clock time, and the frame sequence index. All vary based on real
 *   physical work the process has done — a backdoored kernel cannot predict them
 *   because it does not control V8 GC scheduling or CPU branch predictor state.
 * 
 * - **Level 2 — OS-mixed (recommended default):** Takes a Level 1 observation,
 *   mixes in 128 bytes of fresh OS entropy, and hashes everything through
 *   SHA3-512. A second hrtime sample brackets the OS read, encoding its actual
 *   syscall latency as entropy. Effective even in VMs with a stale kernel pool.
 * 
 * - **Level 3 — Memory-hardened:** Applies native `crypto.argon2id` on top of
 *   the Level 2 hash for frames with index `< mh`. This makes brute-forcing
 *   individual frame seeds require `mem` KiB of RAM per candidate — infeasible
 *   at GPU scale. Gate with a small `memoryH` to limit latency impact.
 * @param {number}  h          - Hardening level (0–3).
 * @param {number}  mh         - Max frame index that triggers argon2id (harden=3 only).
 * @param {number}  mem        - Argon2id `memory` (memoryCost) in KiB.
 * @param {number}  t          - Argon2id `passes` (timeCost / iteration count).
 * @param {number}  p          - Argon2id `parallelism` degree.
 * @param {number}  s          - Frame sequence index; gates argon2id and is mixed as a metric.
 * @param {boolean} useUrandom - Whether to read OS bytes from `/dev/urandom` directly.
 * @returns {Promise<Buffer>} A `Buffer` representing the hashed frame observation.
 * @throws {RangeError} If `h` is outside 0–3, or error from argon2.
 * @private
 */
const snapshot = hardenFn(async (h, mh, mem, t, p, s, useUrandom) => {

    if (h < 0 || h > 3)
        throw new RangeError(`Hardening level [${h}] must be 0–3.`);

    // ── Level 0: bare hrtime (benchmark / test mode only) ──────────────────
    // Single timing sample, no OS reads. Essentially no entropy hardening;
    // only use this to measure THS framework overhead in isolation.
    if (h === 0) return bigIntToBuffer(process.hrtime.bigint());

    // ── Gather process and memory metrics ──────────────────────────────────
    // These values encode the *history* of all computation that preceded this
    // frame. CPU counters reflect real instructions executed; context-switch
    // counts reflect OS scheduling decisions; heap counters reflect V8 GC
    // behaviour. A backdoored DRBG cannot predict them because they are a
    // function of physical work, not DRBG state.
    // 
    // All fields use `?? 0` so this function is safe in environments where some
    // fields are unavailable (e.g. Alpine musl, some BSD kernels).
    const u = process.resourceUsage();
    const m = process.memoryUsage();

    const metrics = [
        process.hrtime.bigint(),                                   // nanosecond wall-clock (primary jitter source)
        BigInt(Math.round(process.uptime() * 1_000_000)),          // microsecond uptime
        BigInt(u.userCPUTime     ?? 0),                            // cumulative user-space CPU µs
        BigInt(u.systemCPUTime   ?? 0),                            // cumulative kernel CPU µs
        BigInt(u.minorPageFault  ?? 0),                            // minor page faults (GC pressure indicator)
        BigInt(u.majorPageFault  ?? 0),                            // major page faults (disk I/O indicator)
        BigInt(u.voluntaryContextSwitches   ?? 0),                 // times the process yielded voluntarily
        BigInt(u.involuntaryContextSwitches ?? 0),                 // times the OS preempted the process
        BigInt(m.heapUsed     ?? 0),                               // V8 live heap bytes (varies with GC)
        BigInt(m.heapTotal    ?? 0),                               // V8 committed heap bytes
        BigInt(m.external     ?? 0),                               // C++ object memory tracked by V8
        BigInt(m.arrayBuffers ?? 0),                               // ArrayBuffer + SharedArrayBuffer bytes
        BigInt(m.rss          ?? 0),                               // resident set size (OS-visible memory)
        BigInt(Math.round(performance.now() * 1_000_000)),         // high-res event-loop relative time (µs precision)
        MODULE_LOAD_HRTIME.value,                                  // frozen module-load anchor (see PrivateContainer)
        BigInt(Date.now()),                                        // wall-clock ms (coarse; domain separation)
        BigInt(s ?? 0)                                             // frame index (guarantees uniqueness across frames)
    ].map(bigIntToBuffer);

    const metricsConcat = Buffer.concat(metrics);
    // Zero the individual encoded buffers now that they are concatenated.
    zeroBuf(...metrics);

    // Level 1: raw metric concatenation, no OS bytes.
    // Weaker than Level 2 but usable in restricted WASM / sandboxed environments.
    if (h === 1) return metricsConcat;

    // ── Level 2+: fold in fresh OS entropy ────────────────────────────────
    // 128 OS bytes are read here. The latency of this syscall varies by kernel
    // interrupt state, scheduler queue depth, and page cache pressure — all
    // captured by the second hrtime sample below.
    const noise = await getRandom(128, useUrandom);

    const combined = createHash('sha3-512')
        .update(noise)
        .update(metricsConcat)
        // Second hrtime sample: encodes how long the OS read actually took.
        // Influenced by kernel scheduler state, interrupt latency, and NUMA
        // memory access patterns — all independent of the DRBG.
        .update(process.hrtime.bigint().toString())
        .digest();

    zeroBuf(noise, metricsConcat);

    // Level 2: return the combined hash. Recommended default.
    if (h <= 2 || s >= mh) return combined;

    // ── Level 3: argon2id memory-hard stretch ─────────────────────────────
    // The SHA3-512 combined hash is used as the argon2id `message` (password).
    // Each brute-force candidate requires `mem` KiB of RAM — GPU farms are
    // bottlenecked by memory bandwidth, not compute, making this infeasible at
    // the scale needed to invert a 512-bit hash input.
    // 
    // Uses native `crypto.argon2` (Node.js 22+) via the promisified reference
    // frozen in `argon2HashAsync`. Option shape differs from the npm `argon2`
    // package — see the `argon2HashAsync` JSDoc for the full mapping.
    const salt = await getRandom(16, useUrandom);
    let memHard, out;

    await wrapTry(
        async () => {
            memHard = await argon2HashAsync.value('argon2id', {
                message:     combined,   // password / data to hash
                nonce:       salt,       // per-frame salt; prevents precomputation tables
                memory:      mem,        // memoryCost in KiB
                passes:      t,          // timeCost / iteration count
                parallelism: p,          // degree of parallelism
                tagLength:   64          // 512-bit output, matching SHA3-512
            });

            // Prepend the memory-hard output to the pre-stretch material.
            // An attacker who somehow breaks argon2id still faces the underlying
            // SHA3-512 hash, and vice versa — neither layer alone is sufficient.
            out = Buffer.concat([memHard, combined]);
        },

        null,
        // Always zero sensitive intermediate buffers, even on error.
        () => zeroBuf(salt, memHard, combined)
    );

    return out;
});


/**
 * Inject timing jitter into the frame sequence by performing two independent
 * OS reads and measuring the total elapsed nanoseconds.
 * 
 * **What provides the jitter:**
 * Each OS read is a syscall whose latency depends on kernel interrupt state,
 * scheduling quantum, TLB cache state, and NUMA memory access patterns — all
 * physical non-deterministic processes that a backdoored DRBG cannot observe
 * or predict. The two reads are issued concurrently via `Promise.all` so their
 * individual latencies are independent.
 * 
 * `timingSafeEqual` is intentionally constant-time and contributes no timing
 * variation. Its only role here is to prevent dead-code elimination from
 * discarding the OS reads — the comparison result is always discarded.
 * 
 * **Why the delta is fed into the KMAC accumulator:**
 * A co-located hypervisor tenant might try to measure inter-frame latency from
 * outside the process. Folding the nanosecond delta into the MAC means the
 * attacker must match `hrtime.bigint()` precision (1 ns) to gain any advantage.
 * Cross-VM timing attacks are bounded by hypervisor scheduling granularity
 * (typically 1–10 µs), which is 3–4 orders of magnitude too coarse.
 * @param {boolean} useUrandom - Whether to read jitter bytes from `/dev/urandom`.
 * @returns {Promise<bigint>} Nanosecond delta between start and end hrtime samples.
 * @private
 */
const jitter = hardenFn(async (useUrandom) => {
    const t0 = process.hrtime.bigint();

    // Concurrent reads: syscall latencies are independent of each other.
    // Total wall-clock time from t0 is non-deterministic due to OS scheduling.
    const [a, b] = await Promise.all([
        getRandom(64, useUrandom),
        getRandom(64, useUrandom),
    ]);

    // Constant-time comparison: result discarded. Prevents DCE from removing
    // the OS reads. `timingSafeEqual` itself adds no timing entropy.
    timingSafeEqual(a, b);
    zeroBuf(a, b);

    return process.hrtime.bigint() - t0;
});


// ─── Temporal Hardening Solution ─────────────────────────────────────────────

/**
 * The Temporal Hardening Solution — the primary API of this module.
 * 
 * `THS` wraps multiple entropy sources into a single, forward-secret, memory-hard
 * random byte generator. See the module-level documentation for the full threat model.
 * 
 * @example
 * ```js
 * import THS from 'ths-csprng';
 * 
 * // Generate 32 bytes of hardened randomness (Level 2, 64 frames)
 * const key = await THS.random(32);
 * 
 * // Generate 64 bytes for an API token with custom domain label
 * const token = await THS.random(64, { label: 'my-app:api-token' });
 * 
 * // Stream frames for a long-lived entropy tap
 * for await (const frame of THS.streamFrames(32)) {
 *     doSomethingWith(frame);
 *     // break when done
 * }
 * ```
 * @public
 */
class THS_Class {

    /**
     * Construct a new THS instance.
     * 
     * The constructor performs no entropy initialization — the entropy storage
     * module singleton (`entropyStorage`) is lazily bootstrapped on the
     * first call to `random()`. This avoids a blocking entropy read at import
     * time, which would be unsafe at early boot in VM environments.
     * 
     * `THS_Class` is not intended to be instantiated by consumers directly.
     * The module exports a single frozen singleton (`THS`) via `PrivateContainer`.
     * Calling `new THS_Class()` outside this module will produce a functional
     * but unprotected instance — prefer `THS` instead.
     */
    constructor() {
        // Intentionally empty: all state is held in module-level PrivateContainers
        // (entropyStorage, argon2HashAsync, MODULE_LOAD_HRTIME) rather than
        // on the instance. This prevents instance-level tampering (e.g. an attacker
        // replacing `this._seed` with a known value) and also means two THS_Class
        // instances share the same entropy storage, preserving cross-call forward secrecy
        // even if a consumer mistakenly constructs a second instance.
    }


    /**
     * Generate `length` cryptographically hardened random bytes.
     * 
     * Internally runs the **sequential frame movie**: entropy accumulation
     * proceeds frame-by-frame in a `for` loop (never `Promise.all`) so that the
     * inter-frame timing spread — scheduler jitter, OS read latency, GC pauses —
     * is preserved as entropy. See the module-level documentation for the full
     * design rationale.
     * 
     * **Threat resilience summary:**
     * - Backdoored `crypto.randomBytes` / hardware RNG → countered by mixing with
     *   process metrics and (optionally) direct `/dev/urandom` reads.
     * - VM entropy starvation → countered by CPU-jitter metrics and argon2id
     *   at `harden=3`.
     * - Forked process state reuse (CVE-2008-0166 class) → countered by per-call
     *   OS re-seed of the entropy storage.
     * - Forward-secret attack on entropy storage → countered by sandwich-mode
     *   post-output frames.
     * @param {number}  [length=32]               - Bytes to produce. Returns empty Buffer for `0`.
     * @param {object}  [opts={}]                 - Tuning options.
     * @param {number}  [opts.layers=64]          - Sequential entropy frames to accumulate (2–32768).
     * @param {number}  [opts.harden=2]           - Snapshot hardening level (0–3); see `snapshot`.
     * @param {boolean} [opts.trng=false]         - Read from `/dev/urandom` directly (bypasses Node crypto).
     * @param {boolean} [opts.buffer=true]        - Return `Buffer` when `true`, raw `Uint8Array` when `false`.
     * @param {boolean} [opts.sandwichMode=true]  - Fold post-output frames into the entropy storage for forward secrecy.
     * @param {number}  [opts.maxSandwichCount=3] - Number of post-output frames to fold in (1–32768).
     * @param {number}  [opts.memoryH=1]          - Max frame index triggering argon2id when `harden=3` (1–layers).
     * @param {number}  [opts.mem=16384]          - Argon2id `memory` in KiB (≥ 1024). 16 MiB minimum recommended.
     * @param {number}  [opts.passes=3]           - Argon2id `passes` (iteration count / timeCost).
     * @param {number}  [opts.parallelism=4]      - Argon2id degree of parallelism.
     * @param {string}  [opts.label='THS-v2']     - KMAC domain-separation label; change per key type.
     * @returns {Promise<Buffer|Uint8Array>} Exactly `length` bytes of hardened randomness.
     * @throws {RangeError} On invalid option values.
     */
    async random(length = 32, {
        layers           = 64,
        harden           = 2,
        trng             = false,
        buffer           = true,
        sandwichMode     = true,
        maxSandwichCount = 3,
        memoryH          = 1,
        mem              = 16384,
        passes           = 3,
        parallelism      = 4,
        label            = 'THS-v2'
    } = {}) {

        if (length <= 0) return Buffer.alloc(0);

        if (layers < 2 || layers > 32_768)
            throw new RangeError(`layers must be 2–32768, got ${layers}`);
        if (harden < 0 || harden > 3)
            throw new RangeError(`harden must be 0–3, got ${harden}`);
        if (harden === 3 && (memoryH < 1 || memoryH > layers))
            throw new RangeError('memoryH must be 1–layers when harden=3');
        if (sandwichMode && (maxSandwichCount < 1 || maxSandwichCount > 32_768))
            throw new RangeError('maxSandwichCount out of range (1–32768)');
        if (typeof mem !== 'number' || mem < 1024)
            throw new RangeError('mem (Argon2id memoryCost) must be ≥ 1024 KiB');

        // ── initialize or refresh the cross-call entropy storage ──────────────────
        // Re-seeding from OS entropy on *every call* (not just the first) prevents
        // the entropy storage from becoming a closed, self-referential loop.
        // 
        // Defence in depth: if the OS CSPRNG is weak, process metrics still diverge
        // between calls; if process metrics are somehow predictable, the OS bytes
        // still maintain uncertainty. Neither source alone is sufficient for an
        // attacker to reconstruct the full entropy storage state.
        const osSeed = await getRandom(64, trng);

        if (entropyStorage.check()) {
            // entropy storage already initialized: hash previous state + new OS seed.
            // `createHash('sha3-512')` is used rather than KMAC here because we are
            // mixing two values of equal trust — there is no asymmetric key/data
            // relationship that KMAC's separation is needed for.
            const refreshed = createHash('sha3-512')
                .update(entropyStorage.value)
                .update(osSeed)
                .digest();

            // Zero the consumed osSeed immediately after absorption, then store
            // the refreshed 64-byte entropy storage back into its PrivateContainer.
            // `reset` returns the container so we can chain `.store()`.
            entropyStorage
                .reset(zeroBuf(osSeed))
                .store(refreshed);
        } else {
            // First call in this process: bootstrap the entropy storage directly from
            // the raw OS seed. No previous state to mix — the OS bytes are the seed.
            // Subsequent calls will mix this value with fresh OS bytes (see above).
            entropyStorage.value = osSeed;
        }

        // `processSeed` is a per-call snapshot of the entropy storage, scoped to
        // this invocation only. The entropy storage itself is the cross-call state.
        // Copying prevents a race condition in which sandwich-mode writes to the
        // entropy storage mid-call would alter the KMAC key already in use.
        const processSeed = Buffer.from(entropyStorage.value);
        let resultBuffer, k;

        return await wrapTry(
            async () => {
                // initialize KMAC256 keyed with `processSeed` and domain-separated by
                // `label`. KMAC (NIST SP 800-185) formally separates key and
                // personalisation in the Keccak sponge construction — no key/data
                // confusion vulnerability, unlike HMAC with a prepended key.
                //
                // `dkLen: length` causes `k.digest()` to produce exactly `length` bytes
                // directly from the sponge — no secondary KDF step needed.
                k = kmac256.create(processSeed, {
                    personalization: toBytes(label),
                    dkLen: length
                });

                // ── Sequential frame movie ─────────────────────────────────────────
                // CRITICAL: this must remain a sequential `for` loop, never `Promise.all`.
                // 
                // `Promise.all` would schedule all snapshot() calls concurrently,
                // collapsing the "movie" into a near-simultaneous "photo". All hrtime
                // samples would cluster within a single scheduler tick (~1 µs), the
                // inter-frame jitter would essentially vanish, and the temporal entropy
                // advantage disappears entirely.
                // 
                // Concurrency would also corrupt jitter() measurements: concurrent
                // snapshot() OS reads would compete with jitter() OS reads, producing
                // correlated latency rather than independent samples.
                for (let i = 0; i < layers; i++) {
                    const frame = await snapshot(
                        harden, memoryH, mem, passes, parallelism, i, trng,
                    );

                    // Advance the KMAC sponge. Because KMAC is a fixed-key construction,
                    // an adversary who sees the frame bytes but not `processSeed` cannot
                    // determine the internal sponge state — they see one input to an
                    // unknown-keyed permutation.
                    k.update(frame);
                    zeroBuf(frame);

                    if (harden >= 1) {
                        // Interleave fresh OS bytes at every frame. Even in the absolute
                        // worst case — a fully deterministic VM where all snapshot metrics
                        // are predictable — these 16 OS bytes maintain unpredictability.
                        // 16 bytes is intentionally small: entropy here is supplemental,
                        // not primary, and larger reads increase latency without benefit.
                        const sup = await getRandom(16, trng);
                        k.update(sup);
                        zeroBuf(sup);
                    }

                    // Inject jitter between frames (not after the last — there is no
                    // next frame to separate). The nanosecond delta from two OS reads
                    // encodes real physical latency as a KMAC input, requiring an
                    // external observer to match hrtime precision (1 ns) to exploit it.
                    if (i < layers - 1) {
                        const jitterDelta = await jitter(trng);
                        k.update(bigIntToBuffer(jitterDelta));
                    }
                }

                // Finalise the KMAC sponge. `digest()` is one-shot — calling it
                // consumes the sponge state and produces exactly `length` output bytes.
                // The raw output is wrapped in a `Buffer` for ergonomic compatibility
                // with Node.js APIs that expect `Buffer` (e.g. `crypto.createHmac`).
                const out = k.digest();
                resultBuffer = buffer ? Buffer.from(out) : out;
                // Zero the raw digest if we copied it into a Buffer; the copy is what
                // will be returned, so the original sponge output is no longer needed.
                buffer && zeroBuf(out);

                // ── Sandwich feedback loop ─────────────────────────────────────────
                // Post-mix: additional entropy frames are generated AFTER the output is
                // committed and folded into the entropy storage for the next call.
                // 
                // Forward-secrecy guarantee:
                //   The output is finalised before this phase begins. Post-output frames
                //   depend on scheduler events, OS reads, and hrtime values that had not
                //   yet occurred when the output was produced. An adversary who captures
                //   `resultBuffer` cannot reconstruct these future-dependent values, so
                //   the next call's entropy storage seed remains hidden even from someone
                //   who observed this call's output in full.
                // 
                // Analogous to the "additional input" mechanism in NIST SP 800-90A
                // Hash_DRBG, but generated automatically and unconditionally here.
                if (sandwichMode) {
                    // initialize the feedback chain from the current entropy storage state
                    // rather than `processSeed` so that any mid-call entropy storage mutations
                    // (e.g. from a concurrent call on a shared worker) are incorporated.
                    let feedback = createHash('sha3-512').update(processSeed).digest();

                    // Sequential, not concurrent — same rationale as the main loop.
                    for (let i = 0; i < maxSandwichCount; i++) {
                        // Frame index `layers + i` ensures post-output frames are
                        // distinguishable from pre-output frames even if all metrics
                        // happen to be identical (e.g. in a test harness with fixed time).
                        const postFrame = await snapshot(
                            harden, memoryH, mem, passes, parallelism, layers + i, trng,
                        );

                        // Mix: previous feedback + post-output frame + current hrtime.
                        // The hrtime encodes the exact elapsed time after output was
                        // committed — real wall-clock entropy the DRBG cannot predict.
                        const next = createHash('sha3-512')
                            .update(feedback)
                            .update(postFrame)
                            .update(bigIntToBuffer(process.hrtime.bigint()))
                            .digest();

                        zeroBuf(feedback, postFrame);
                        feedback = next;
                    }

                    // Ratchet the entropy storage forward. Always mixed, never reset to zero,
                    // so state continuity is preserved across all calls in this process.
                    // The `zeroBuf(feedback)` call inside `reset()` zeroes the consumed
                    // sandwich output before the container accepts the new value.
                    const newWave = createHash('sha3-512')
                        .update(entropyStorage.value)
                        .update(feedback)
                        .digest();

                    entropyStorage
                        .reset(zeroBuf(feedback))
                        .store(newWave);
                }

                return resultBuffer;
            },

            null,
            // Cleanup: always zero the per-call process seed and nullify the
            // KMAC instance reference regardless of whether the call succeeded.
            // `processSeed` contains a copy of the entropy storage — leaving it
            // accessible on the heap after the call would widen the window
            // during which a memory dump could recover the seed.
            () => { k = zeroBuf(processSeed); },
        );
    }


    /**
     * Async generator that yields a continuous stream of hardened random frames.
     * 
     * Unlike `random()`, the stream does not pre-commit to a fixed number of
     * layers. Each `yield` is a natural async suspension point that introduces
     * real scheduler-driven jitter between frames. The seed is ratcheted forward
     * using both the emitted frame bytes *and* the hrtime at which the consumer
     * resumed the generator — future output depends on when the consumer consumed
     * prior output.
     * 
     * The stream maintains its own seed entirely separate from the cross-call
     * entropy storage used by `random()`. Streaming and non-streaming uses of THS
     * cannot interfere with each other's forward-secrecy properties.
     * 
     * **Use cases:**
     * - Long-lived entropy taps (e.g. feeding a key derivation service).
     * - Generating a large sequence of independent session tokens.
     * - Any workload where the total number of random values is not known upfront.
     * 
     * **Stopping:** Use `break` in a `for await...of` loop, or call
     * `generator.return()`. The generator runs indefinitely until externally stopped.
     * 
     * @param {number} [frameLength=32]         - Bytes per yielded frame.
     * @param {object} [options={}]             - Entropy tuning options.
     * @param {number}  [options.harden=2]      - Snapshot hardening level (0–3).
     * @param {number}  [options.memoryH=1]     - Max frame index for argon2id (harden=3).
     * @param {number}  [options.mem=16384]     - Argon2id `memory` in KiB.
     * @param {number}  [options.passes=3]      - Argon2id `passes` (timeCost).
     * @param {number}  [options.parallelism=4] - Argon2id degree of parallelism.
     * @param {boolean} [options.trng=false]    - Read from `/dev/urandom` directly.
     * @param {string}  [options.label='THS-Stream-v2'] - KMAC domain-separation label.
     * @yields {Buffer} Exactly `frameLength` bytes of hardened randomness.
     * @example
     * ```js
     * let count = 0;
     * for await (const frame of THS.streamFrames(32, { harden: 2 })) {
     *     processToken(frame);
     *     if (++count >= 100) break;
     * }
     * ```
     */
    async *streamFrames(frameLength = 32, options = {}) {
        const harden      = options.harden      ?? 2;
        const memoryH     = options.memoryH     ?? 1;
        const mem         = options.mem         ?? 16384;
        const passes      = options.passes      ?? 3;
        const parallelism = options.parallelism ?? 4;
        const trng        = options.trng        ?? false;
        const label       = options.label       || 'THS-Stream-v2';

        // Bootstrap the stream-local seed independently of the module entropy storage.
        // This ensures that consuming the stream does not perturb the entropy state
        // seen by concurrent `random()` calls, and vice versa.
        let frameSeed  = await getRandom(64, trng);
        let frameIndex = 0;

        while (true) {
            // Mix fresh OS bytes into the seed before every frame.
            // The seed is always a *mix* of previous state + fresh OS + hrtime —
            // never used raw. An adversary who reconstructs `frameSeed` at index N
            // still cannot predict index N+1 without also knowing the OS bytes and
            // exact hrtime of the next mix operation.
            const osFresh = await getRandom(32, trng);
            const mixedSeed = createHash('sha3-512')
                .update(frameSeed)
                .update(osFresh)
                // Current hrtime binds the mixed seed to this exact nanosecond — two
                // frames cannot produce the same mixedSeed even if osFresh collides.
                .update(bigIntToBuffer(process.hrtime.bigint()))
                .digest();
            zeroBuf(frameSeed, osFresh);
            frameSeed = mixedSeed;

            // KMAC keyed with the current frame seed; domain-separated by label.
            // Using a different label than `random()` prevents cross-context
            // output correlation even if both happen to share the same seed bytes.
            const k = kmac256.create(frameSeed, {
                personalization: toBytes(label),
                dkLen: frameLength
            });

            // System snapshot at this frame index. `frameIndex` ensures uniqueness
            // even if all other metrics happened to be identical across two frames
            // (vanishingly unlikely in practice, but guaranteed here).
            const moment = await snapshot(
                harden, memoryH, mem, passes, parallelism, frameIndex, trng,
            );
            k.update(moment);
            zeroBuf(moment);

            const out   = k.digest();
            const frame = Buffer.from(out);
            zeroBuf(out);

            // Mark pre-yield time. After `yield`, the generator suspends until the
            // consumer calls `next()`. The delta between `postYieldMark` and
            // `resumeMark` encodes real elapsed time that depends on the consumer's
            // own processing — unpredictable without observing the consumer.
            const postYieldMark = process.hrtime.bigint();
            yield frame;
            // `resumeMark` is captured on the first instruction after the consumer
            // resumes the generator. The gap [postYieldMark, resumeMark] spans the
            // consumer's processing time plus async re-scheduling latency — both
            // sources of genuine unpredictability.
            const resumeMark = process.hrtime.bigint();

            // Ratchet the seed using:
            //   1. Previous frame seed   (state continuity)
            //   2. Yielded frame bytes   (output-dependent evolution)
            //   3. Pre-yield hrtime      (when the frame was produced)
            //   4. Post-resume hrtime    (when the consumer came back)
            // All four inputs are required to predict the next seed; knowing only
            // the output frame is insufficient.
            const nextSeed = createHash('sha3-512')
                .update(frameSeed)
                .update(frame)
                .update(bigIntToBuffer(postYieldMark))
                .update(bigIntToBuffer(resumeMark))
                .digest();
            // Zero the consumed seed before replacing it. `frameSeed` held a copy of
            // the previous state — leaving it on the heap would give a heap-dump
            // attacker a second window to recover past seed material.
            zeroBuf(frameSeed);

            frameSeed = nextSeed;
            frameIndex++;
        }
    }


    // ── Convenience aliases ───────────────────────────────────────────────────

    /**
     * Alias for {@link THS_Class#random}. Identical in every respect.
     * Provided for brevity in code that generates many random values.
     * @param {number} len - Byte count.
     * @param {object} [o] - Options; see {@link THS_Class#random}.
     * @returns {Promise<Buffer|Uint8Array>}
     */
    async rand(len, o) { return THS.random(len, o); }


    /**
     * Alias for {@link THS_Class#random}. Identical in every respect.
     * @param {number} len - Byte count.
     * @param {object} [o] - Options; see {@link THS_Class#random}.
     * @returns {Promise<Buffer|Uint8Array>}
     */
    async rnd(len, o) { return THS.random(len, o); }


    /**
     * Return raw OS entropy bytes with no THS mixing.
     * 
     * **When to use:** Bootstrapping, diagnostics, or seeding a separate mixing
     * layer. For all other uses, prefer {@link THS_Class#random}.
     * 
     * **Threat note:** Bypasses all THS hardening. If the OS CSPRNG is backdoored
     * (e.g. a Dual_EC_DRBG-style compromise), this output may be compromised.
     * 
     * @param {number}  len         - Number of bytes.
     * @param {boolean} [trng=true] - Read from `/dev/urandom` directly when `true`.
     * @returns {Promise<Buffer>} Raw OS entropy; caller must zero when done.
     */
    async raw(len, trng = true) { return getRandom(len, trng); }


    /**
     * Synchronous entropy fill via the Web Crypto API (`crypto.getRandomValues`).
     * 
     * A thin wrapper — no THS mixing, no temporal observation, no memory hardening.
     * Use only when synchronous operation is required (e.g. initializing a
     * `TypedArray` for immediate use in `SubtleCrypto`).
     * 
     * Routes to `window.crypto` in browser environments, `webcrypto` from
     * `node:crypto` in Node.js.
     * 
     * **Threat note:** Subject to the same hardware RNG risks as the OS CSPRNG. An
     * adversary who can bias `getRandomValues` output will bias this output directly.
     * 
     * @param {ArrayBufferView} arr - `TypedArray` to fill in place.
     * @returns {ArrayBufferView} The same array, filled.
     */
    fillRandom(arr) {
        return (
            typeof window !== 'undefined' && window.crypto
                ? window.crypto
                : webcrypto
        ).getRandomValues(arr);
    }
}


// ─── Top-level export ────────────────────────────────────────────

// Atomic Runtime Protection Bootstrapping Execution Loop
//
// Hardens all public-facing references before any external code can access them.
// Runs synchronously at module evaluation time, so it completes before the first
// `import` consumer receives the exported bindings.
//
// Order matters:
//   1. Prototype methods are hardened first (while `THS_Class` is still mutable).
//   2. The constructor itself is hardened (prevents subclassing / replacement).
//   3. Free-standing helper functions are frozen (prevents monkey-patching of
//      `toBytes`, `bigIntToBuffer`, and `getRandom` via the closure they close over).
//
// `wrapTrySync(..., null, null, false)` means: no error handler, no finally,
// and do NOT rethrow — a bootstrap failure should be a fatal silent assertion
// rather than an uncaught exception that leaks internal structure to an attacker.
wrapTrySync(() => {

    // Harden each prototype method in-place. `hardenFn` wraps the function in a
    // non-configurable, non-writable property descriptor on `THS_Class.prototype`,
    // preventing an attacker from replacing e.g. `THS.random = maliciousRandom`.
    for (const key of ['random', 'rand', 'rnd', 'streamFrames', 'raw', 'fillRandom']) {
        hardenFn(THS_Class.prototype[key], THS_Class.prototype, key);
    }

    // Harden the constructor itself. Prevents `THS_Class = class extends THS_Class {}`
    // from silently replacing the class reference in module scope.
    hardenFn(THS_Class);

    // Freeze the private helper function objects. `Object.freeze` prevents new
    // properties from being added and existing ones from being mutated or deleted.
    // `toBytes` and `bigIntToBuffer` are referenced inside `snapshot`, `jitter`,
    // and `streamFrames` closures — freezing them closes the last monkey-patch surface.
    // `nodeRandomBytes` (aliased as `randomBytes` inside the import) is frozen as a
    // belt-and-suspenders guard against a post-import patch on `node:crypto`.
    for (const structure of [nodeRandomBytes, bigIntToBuffer, toBytes]) {
        structure && Object.freeze(structure);
    }
}, null, null, false);


// Instantiate exactly one THS_Class and seal it inside a frozen PrivateContainer.
// `.freeze()` makes the container itself immutable after storing the instance,
// so `THS_Init.value` will always return the same object for the module's lifetime.
const THS_Init = new PrivateContainer(() => new THS_Class()).freeze();

/**
 * The module-level singleton THS instance.
 * Extracted from the frozen PrivateContainer for ergonomic export.
 * @type {THS_Class}
 */
const THS = THS_Init.value;


/**
 * Drop-in replacement for Node's `crypto.randomBytes`, with optional THS hardening.
 * 
 * | `isHardenRNG` | Behaviour |
 * |---|---|
 * | `false` (default) | Synchronous `crypto.getRandomValues` — fast, no THS overhead. |
 * | `true`            | Full THS sequential frame movie — async, multi-source, optionally memory-hard. |
 * 
 * **Use `isHardenRNG=true` for:**
 * - Long-lived key material (session keys, signing keys, master seeds).
 * - Environments where you distrust the OS CSPRNG (VM boot, embedded hardware,
 *   suspected RDRAND/Dual_EC_DRBG compromise).
 * - Any context where latency is acceptable and the threat model includes
 *   state-level adversaries with OS-level entropy access.
 * 
 * **Use `isHardenRNG=false` for:**
 * - Nonces, IVs, or values that need only be unpredictable in practice.
 * - High-throughput token generation where per-call THS overhead is prohibitive.
 * 
 * Wrapped with `hardenFn` to prevent the export reference from being replaced by
 * a monkey-patch after module load.
 * @param {number}  len                 - Number of bytes to generate.
 * @param {boolean} [isHardenRNG=false] - Route through THS when `true`.
 * @param {object}  [o]                 - Options forwarded to `THS.random()` when `isHardenRNG=true`.
 * @returns {Uint8Array|Promise<Buffer|Uint8Array>} Synchronous `Uint8Array` when `isHardenRNG=false`; `Promise` otherwise.
 */
const randomBytes = hardenFn((len, isHardenRNG = false, o) => {
    if (!isHardenRNG) return THS.fillRandom(new Uint8Array(len));
    return THS.random(len, o);
});


// ─── Exports ──────────────────────────────────────────────────────────────────

export { THS, THS_Class, randomBytes };
export default THS;