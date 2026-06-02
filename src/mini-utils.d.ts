/**
 * A hardened runtime container for isolated value storage.
 * Enforces rigid scoping boundaries for sensitive primitives or dynamic function evaluations.
 * Provides defensive mitigations against global prototype tampering and memory residual leakage.
 * Designed to secure global constant structures or safely replace unsafe soft-private conventions (e.g., `_privateValue`).
 * @template T - The type of the underlying payload stored within the container.
 * @public
 */
export class PrivateContainer<T> {
    /**
     * @param {(() => T) | T} [val] - Initial storage payload configuration or functional evaluation block.
     * @param {boolean} [isCall=true] - Set to `false` to intercept dynamic execution and store functional variables raw.
     * @example
     * // Store a primitive value directly
     * const vault = new PrivateContainer('secret-key');
     * // Store a lazily evaluated value (invokes the function immediately)
     * const lazyVault = new PrivateContainer(() => generateToken());
     * // Store a raw function execution payload without invoking it
     * const activeVault = new PrivateContainer(() => 'i am a function', false);
     */
    constructor(val?: (() => T) | T, isCall?: boolean);
    /**
     * Setter to overwrite the internal allocation window.
     * @note JavaScript setters ignore intentional return statements; assignment statements always evaluate to the operand value.
     * @param {(() => T) | T} val - Target entry allocation value or evaluation block.
     * @example
     * const vault = new PrivateContainer();
     * vault.value = 'secret';
     * // Updates using functions follow instance state configuration:
     * const lazyVault = new PrivateContainer(undefined, true);
     * lazyVault.value = () => 'computed-secret';
     * console.log(lazyVault.value); // Output: 'computed-secret'
     */
    set value(val: (() => T) | T);
    /**
     * Getter for the internal reference payload.
     * @returns {T | undefined} The targeted reference payload, or `undefined` if unallocated or purged.
     * @example
     * const vault = new PrivateContainer(81);
     * console.log(vault.value); // Output: 81
     */
    get value(): T | undefined;
    /**
     * Directly updates the internal allocation slot while adhering to instance execution lock configurations.
     * Functionally identical to {@link PrivateContainer#value}, but supports fluent chaining.
     * @param {(() => T) | T} val - Target entry allocation value or functional evaluation block.
     * @returns {this} The instance context window reference for fluent method chaining.
     * @example
     * const vault = new PrivateContainer();
     * vault.store('direct-payload');
     */
    store(val: (() => T) | T): this;
    /**
     * Configures or flips the function unwrapping behavior state flag of this instance container.
     * Allows seamless runtime adjustments to execution blocks before value mutations are assigned.
     * @param {boolean} [isCall] - Explicit override setting. If omitted, flips the current boolean state.
     * @returns {this} The instance context window reference for fluent method chaining.
     * @example
     * const vault = new PrivateContainer();
     * // Temporarily disable unwrapping
     * vault.toggleCall(false).value = () => 'system-callback';
     * // Flip back to enabling dynamic execution blocks
     * vault.toggleCall();
     */
    toggleCall(isCall?: boolean): this;
    /**
     * Evaluates whether the container currently maintains a truthy footprint allocation.
     * @returns {boolean} `true` if the internal value evaluates to truthy, `false` otherwise.
     * @example
     * const vault = new PrivateContainer(null);
     * console.log(vault.check()); // Output: false
     */
    check(): boolean;
    /**
     * Checks whether the underlying storage reference is unallocated (`null` or `undefined`).
     * @returns {boolean} `true` if the current payload state is nullish, `false` otherwise.
     * @example
     * const vault = new PrivateContainer();
     * console.log(vault.isEmpty()); // Output: true
     */
    isEmpty(): boolean;
    /**
     * Triggers deep memory scrubbing over the underlying memory layout context to zero-out data footprints,
     * then flushes the primary internal capsule storage index safely to an `undefined` value state.
     * @note Operation will fail silently if the container has already transitioned to a frozen state.
     * @returns {this} The instance context window reference for fluent method chaining.
     * @example
     * const keyVault = new PrivateContainer(new Uint8Array([1, 2, 3, 4]));
     * keyVault.reset(); // Zeroes the underlying array buffer memory instantly, then sets internally to undefined
     */
    reset(): this;
    /**
     * Permanently transitions the container instance layout into an immutable structural lock.
     * Disables future data mutations, setter overrides, or memory clearing executions.
     * @param {boolean} [isReset=false] - If `true`, explicitly executes an immediate memory purge via `.reset()` prior to invoking the structural lock phase.
     * @returns {Readonly<this>} The structurally locked, read-only container instance interface.
     * @example
     * const vault = new PrivateContainer('immutable-config').freeze();
     * vault.value = 'hacked'; // Fails silently, value remains unchanged
     * console.log(vault.value); // Output: 'immutable-config'
     */
    freeze(isReset?: boolean): Readonly<this>;
    /**
     * Check if the current instance is frozen — in which case mutations can no longer be accepted.
     * @returns {boolean} `true` if the current instance is frozen.
     * @example
     * const vault = new PrivateContainer('data');
     * console.log(vault.isFrozen()); // Output: false
     * vault.freeze();
     * console.log(vault.isFrozen()); // Output: true
     */
    isFrozen(): boolean;
    #private;
}
/**
 * Permanently locks and strips metadata flags (or customize name) from target execution objects.
 * Wraps functions inside unconfigurable, non-writable, and non-enumerable property descriptors.
 * @type {(fn: Function, targetObject?: object | null, propertyKey?: string | symbol | null) => Function}
 * @param {Function} fn - The target function to be structurally locked and anonymized.
 * @param {object|null} [_o=null] - Optional target context object if configuring a specific object property.
 * @param {string|symbol|null} [_k=null] - Optional property key identifier matching the target context object.
 * @param {string} [v=""] - Optional custom name for defining property value. Defaults to anonymize it.
 * @returns {Function} The hardened, tamper-proof wrapped function reference.
 * @inline
 * @internal
 */
export const hardenFn: (fn: Function, targetObject?: object | null, propertyKey?: string | symbol | null) => Function;
/**
 * Overwrites the contents of arbitrary binary data containers with zeroes.
 * Wraps target buffers in a Uint8Array window to safely purge data footprints.
 * Supports typed array views, DataViews, standard ArrayBuffers, SharedArrayBuffers,
 * and custom buffer-like objects with a `.fill()` method.
 * @note This function safely swallows internal errors (e.g., if a buffer is detached,
 * transferred, or frozen) to prevent cleanup routines from crashing the application.
 * @param {...any} args - Multi-argument list of values targeted for clean erasure.
 * @returns {null} Always returns `null`.
 * @public
 */
export const zeroBuf: Function;
/**
 * An asynchronous try-catch-finally wrapper for streamlined control flow.
 * @remarks
 * - Seamlessly handles both synchronous and asynchronous functions by safely awaiting execution blocks.
 * - Guarantees sequential, chronological execution of error hooks (`cb_err`) and finalizers (`cb_last`).
 * @template T - The expected resolve type of the primary logic function.
 * @template E - The expected error type caught in the catch block. Defaults to `unknown`.
 * @template R - The return type of the error callback function (recovery value).
 * @param {() => Promise<T> | T} logic - The core function to execute safely. Must satisfy `isFunction` check.  Can be synchronous or asynchronous.
 * @param {(err: E, partialResult: undefined) => R | Promise<R>} [cb_err] - Optional error callback. Note: `partialResult` will always be `undefined` because if `logic` throws, its assignment never completes.
 * @param {(result: T | undefined) => void | Promise<void>} [cb_last] - Optional finalizer callback (runs like a `finally` block). Receives the successful result `T` from `logic`, or `undefined` if `logic` threw an exception (even if `cb_err` recovers a value).
 * @param {boolean} [isThrow=true] - If `true`, re-throws the caught error after executing all callbacks.
 * @returns {Promise<T | R | undefined>} A promise that resolves to:
 * - The result of `logic` (`T`) on success.
 * - The fallback result of `cb_err` (`R`) if an error was caught and handled.
 * - `undefined` if an error occurred, `isThrow` is false, and no `cb_err` handler was provided.
 * @throws {TypeError} If the provided `logic` argument fails the `isFunction` validation check.
 * @throws {E} Re-throws the original caught error if `isThrow` is true and an exception occurs.
 * @public
 */
export const wrapTry: Function;
/**
 * Synchronous try-catch wrapper for clean flow control.
 * @template T - The return type of the main synchronous logic function.
 * @template E - The expected error type caught in the catch block. Defaults to `unknown`.
 * @template R - The return type of the error callback function.
 * @param {() => T} logic - The core synchronous function to execute. Must satisfy `isFunction` check.
 * @param {(err: E) => R} [cb_err] - Optional synchronous error callback.
 * @param {(result: T | undefined) => void} [cb_last] - Optional synchronous finalizer callback. Receives the successful result `T`, or `undefined` if execution failed.
 * @param {boolean} [isThrow=true] - If `true`, re-throws the caught error after executing callbacks.
 * @returns {T | R | undefined} The result of `logic` on success, the result of `cb_err` on failure, or `undefined` if a failure occurs and no error callback is provided.
 * @throws {TypeError} If the provided `logic` argument fails the `isFunction` validation check.
 * @throws {E} Re-throws the original caught error if `isThrow` is true and an exception occurs during execution.
 * @public
 */
export const wrapTrySync: Function;
