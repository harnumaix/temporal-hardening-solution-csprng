export default THS;
/**
 * The module-level singleton THS instance.
 * Extracted from the frozen PrivateContainer for ergonomic export.
 * @type {THS_Class}
 */
export const THS: THS_Class;
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
export class THS_Class {
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
    random(length?: number, { layers, harden, trng, buffer, sandwichMode, maxSandwichCount, memoryH, mem, passes, parallelism, label }?: {
        layers?: number | undefined;
        harden?: number | undefined;
        trng?: boolean | undefined;
        buffer?: boolean | undefined;
        sandwichMode?: boolean | undefined;
        maxSandwichCount?: number | undefined;
        memoryH?: number | undefined;
        mem?: number | undefined;
        passes?: number | undefined;
        parallelism?: number | undefined;
        label?: string | undefined;
    }): Promise<Buffer | Uint8Array>;
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
    streamFrames(frameLength?: number, options?: {
        harden?: number | undefined;
        memoryH?: number | undefined;
        mem?: number | undefined;
        passes?: number | undefined;
        parallelism?: number | undefined;
        trng?: boolean | undefined;
        label?: string | undefined;
    }): AsyncGenerator<any, void, unknown>;
    /**
     * Alias for {@link THS_Class#random}. Identical in every respect.
     * Provided for brevity in code that generates many random values.
     * @param {number} len - Byte count.
     * @param {object} [o] - Options; see {@link THS_Class#random}.
     * @returns {Promise<Buffer|Uint8Array>}
     */
    rand(len: number, o?: object): Promise<Buffer | Uint8Array>;
    /**
     * Alias for {@link THS_Class#random}. Identical in every respect.
     * @param {number} len - Byte count.
     * @param {object} [o] - Options; see {@link THS_Class#random}.
     * @returns {Promise<Buffer|Uint8Array>}
     */
    rnd(len: number, o?: object): Promise<Buffer | Uint8Array>;
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
    raw(len: number, trng?: boolean): Promise<Buffer>;
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
    fillRandom(arr: ArrayBufferView): ArrayBufferView;
}
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
export const randomBytes: Function;
