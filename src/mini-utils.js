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
 * @file mini-utils.js
 * @summary A zero-dependency runtime hardening utility ecosystem for memory sanitization, 
 * and control-flow fault isolation.
 * @author Aries Harbinger
 * @license Apache-2.0
 */
import { types } from 'node:util';


/**
 * Sets a custom `name` on a function and optionally re-assigns it to an object property in-place.
 * @param {Function} fn - The function to rename.
 * @param {Object|null} [obj=null] - Optional parent object for in-place mutation.
 * @param {string|symbol|null} [key=null] - Property key on `obj` to reassign.
 * @param {Object} [opts={}] - Descriptor overrides for the `name` property.
 * @param {string} [opts.value=''] - The custom name to assign.
 * @param {boolean} [opts.configurable=true] - Whether the `name` property can be redefined later.
 * @param {boolean} [opts.writable=false] - Whether the `name` property can be assigned directly.
 * @param {boolean} [opts.enumerable=false] - Whether `name` appears in enumeration.
 * @returns {Function|void} The renamed function when called standalone; `undefined` when mutating in-place.
 * @private
 */
const fwrapCustom = (fn, obj = null, key = null, { value = '', configurable = true, writable = false, enumerable = false } = {}) => {
    try {
        const r = Object.defineProperty(fn, 'name', { value, configurable, writable, enumerable });

        // Standalone — caller receives the renamed function
        if (obj === null && key === null)
            return r;

        // In-place — mutate the parent object directly
        obj[key] = r;

    } catch (e) { return fn; }
};


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
const hardenFn = (() => {
    return (fn, _o = null, _k = null, v = "") => 
        fwrapCustom(fn, _o, _k, {
            value: v ?? '',
            configurable: false,  // Block any future property descriptor modifications or deletions.
            writable: false,      // Prevent direct variable reassignment of the property.
            enumerable: false     // Isolate the property from iterator loops (`for...in`, `Object.keys`).
        });
})();


/**
 * Evaluates whether a given input is functional code.
 * @param {any} val - The target value to evaluate.
 * @returns {boolean} `true` if the target value evaluates to a function, `false` otherwise.
 * @private
 */
const isFunction = hardenFn((val) => typeof val === 'function');


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
const wrapTry = hardenFn(async (logic, cb_err, cb_last, isThrow = true) => {
    let caughtError = null;
    let d, c;

    try {
        if (!isFunction(logic)) throw new TypeError('wrapTry: Expected an executable function for the core execution block');
        d = await logic();
    }

    catch (e) {
        caughtError = e;
        if (cb_err) c = await cb_err(e, d);
    }

    if (cb_last) await cb_last(d);
    if (caughtError && isThrow) throw caughtError;
    return caughtError ? c : d;

}, null, null, 'wrapTry');


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
const wrapTrySync = hardenFn((logic, cb_err, cb_last, isThrow = true) => {
    let caughtError = null;
    let d, c;

    try {
        if (!isFunction(logic)) throw new TypeError('wrapTrySync: Expected a function for the core execution block');
        d = logic();
    }

    catch (e) {
        caughtError = e;
        c = cb_err?.(e);
    }

    cb_last?.(d);

    if (caughtError && isThrow) throw caughtError;
    return caughtError ? c : d;

}, null, null, 'wrapTrySync');


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
const zeroBuf = hardenFn((...args) => {
    for (const buf of args) {
        if (!buf) continue;

        try {
            if (ArrayBuffer.isView(buf)) {
                new Uint8Array(
                    buf.buffer,
                    buf.byteOffset ?? 0,
                    buf.byteLength ?? buf.buffer?.byteLength ?? 0
                ).fill(0);
            }

            else if (types.isAnyArrayBuffer(buf)) {
                new Uint8Array(buf).fill(0);
            }

            else if (isFunction(buf?.fill)) {
                buf.fill(0);
            }
        }
        catch (err) { } // Ignored - Some buffers may be detached, transferred, or frozen
    }

    return null;
});


/**
 * A hardened runtime container for isolated value storage.
 * Enforces rigid scoping boundaries for sensitive primitives or dynamic function evaluations.
 * Provides defensive mitigations against global prototype tampering and memory residual leakage.
 * Designed to secure global constant structures or safely replace unsafe soft-private conventions (e.g., `_privateValue`).
 * @template T - The type of the underlying payload stored within the container.
 * @public
 */
class PrivateContainer {

     /**
      * The physically isolated reference slot managed by the JavaScript engine runtime.
      * @type {T | undefined} 
      */
     #internalVal;

     /**
      * State flag dictating whether functional updates should be unwrapped via invocation.
      * @type {boolean}
      */
     #isCall;


     /**
      * Mutates the internal reference index if the instance layout state remains unfrozen.
      * @param {T | undefined} val - The payload data or undefined state clearing target.
      * @returns {this} The instance context window reference for fluent method chaining.
      */
     #define(val) { if (!this.isFrozen()) this.#internalVal = val; return this; }

     /**
      * Evaluates the entry argument structure and conditionally resolves closure execution locks.
      * @param {(() => T) | T} val - A raw payload instance of type T, or a lazy evaluation function returning T.
      * @param {boolean} isCall - Control flag to dictate whether functional payloads must be unwrapped.
      * @returns {T} The unwrapped structural target value.
      */
     #call(val, isCall) { return (isCall && isFunction(val)) ? val() : val; }


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
     constructor(val, isCall = true) { 
         this.#isCall = isCall;
         this.#define(this.#call(val, isCall)); 
     }


     /**
      * Getter for the internal reference payload.
      * @returns {T | undefined} The targeted reference payload, or `undefined` if unallocated or purged.
      * @example
      * const vault = new PrivateContainer(81);
      * console.log(vault.value); // Output: 81
      */
     get value() { return this.#internalVal; }

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
     set value(val) { this.store(val); }

     /**
      * Directly updates the internal allocation slot while adhering to instance execution lock configurations.
      * Functionally identical to {@link PrivateContainer#value}, but supports fluent chaining.
      * @param {(() => T) | T} val - Target entry allocation value or functional evaluation block.
      * @returns {this} The instance context window reference for fluent method chaining.
      * @example
      * const vault = new PrivateContainer();
      * vault.store('direct-payload');
      */
     store(val) { return this.#define(this.#call(val, this.#isCall)); }

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
     toggleCall(isCall) { if (!this.isFrozen()) this.#isCall = ('boolean' === typeof isCall) ? isCall : !this.#isCall; return this; }

     /**
      * Evaluates whether the container currently maintains a truthy footprint allocation.
      * @returns {boolean} `true` if the internal value evaluates to truthy, `false` otherwise.
      * @example
      * const vault = new PrivateContainer(null);
      * console.log(vault.check()); // Output: false
      */
     check() { return !!this.#internalVal; }

     /**
      * Checks whether the underlying storage reference is unallocated (`null` or `undefined`).
      * @returns {boolean} `true` if the current payload state is nullish, `false` otherwise.
      * @example
      * const vault = new PrivateContainer();
      * console.log(vault.isEmpty()); // Output: true
      */
     isEmpty() { return null == this.#internalVal; }

     /**
      * Triggers deep memory scrubbing over the underlying memory layout context to zero-out data footprints,
      * then flushes the primary internal capsule storage index safely to an `undefined` value state.
      * @note Operation will fail silently if the container has already transitioned to a frozen state.
      * @returns {this} The instance context window reference for fluent method chaining.
      * @example
      * const keyVault = new PrivateContainer(new Uint8Array([1, 2, 3, 4]));
      * keyVault.reset(); // Zeroes the underlying array buffer memory instantly, then sets internally to undefined
      */
     reset() { return (zeroBuf(this.#internalVal), this.#define(void 0)); }

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
     freeze(isReset = false) {
          isReset && this.reset();
          if (!this.isFrozen()) Object.freeze(this);
          return this;
     }

     /**
      * Check if the current instance is frozen — in which case mutations can no longer be accepted.
      * @returns {boolean} `true` if the current instance is frozen.
      * @example
      * const vault = new PrivateContainer('data');
      * console.log(vault.isFrozen()); // Output: false
      * vault.freeze();
      * console.log(vault.isFrozen()); // Output: true
      */
     isFrozen() { return Object.isFrozen(this); }
}


// Atomic Runtime Protection Bootstrapping Execution Loop
wrapTrySync(() => {

    // Loop through and anonymize the prototype methods
    for (const key of ['store', 'check', 'isEmpty', 'reset', 'freeze', 'isFrozen', 'toggleCall']) {
        hardenFn(PrivateContainer.prototype[key], PrivateContainer.prototype, key);
    }

    // Anonymize the Class constructor itself
    hardenFn(PrivateContainer);

    // Freeze the structures
    for (const structure of [fwrapCustom, isFunction, hardenFn, zeroBuf, wrapTry, wrapTrySync, PrivateContainer.prototype, PrivateContainer]) {
        structure && Object.freeze(structure);
    }

}, null, null, false);


export { PrivateContainer, hardenFn, zeroBuf, wrapTry, wrapTrySync };