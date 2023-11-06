// Copyright 2019-2023 @polkadot/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

import type { WasmCryptoInstance } from '@polkadot/wasm-crypto-init/types';

import { bridge, initBridge } from './init.js';

export { packageInfo } from './packageInfo.js';
export { bridge };

// Removes the first parameter (expected as WasmCryptoInstance) and leaves the
// rest of the parameters in-tack. This allows us to dynamically create a function
// return from the withWasm helper
type PopFirst<T extends unknown[]> =
  T extends [WasmCryptoInstance, ...infer N]
    ? N
    : [];

/**
 * @internal
 * @description
 * This create an extenal interface function from the signature, all the while checking
 * the actual bridge wasm interface to ensure it has been initialized.
 *
 * This means that we can call it
 *
 *   withWasm(wasm: WasmCryptoInstance, a: number, b: string) => Uint8Array
 *
 * and in this case it will create an interface function with the signarure
 *
 *   (a: number, b: string) => Uint8Array
 */
function withWasm <T, F extends (wasm: WasmCryptoInstance, ...params: never[]) => T> (fn: F): (...params: PopFirst<Parameters<F>>) => ReturnType<F> {
  return (...params: PopFirst<Parameters<F>>): ReturnType<F> => {
    if (!bridge.wasm) {
      throw new Error('The WASM interface has not been initialized. Ensure that you wait for the initialization Promise with waitReady() from @polkadot/wasm-crypto (or cryptoWaitReady() from @polkadot/util-crypto) before attempting to use WASM-only interfaces.');
    }

    return fn(bridge.wasm, ...params) as ReturnType<F>;
  };
}


export const ed25519KeypairFromSeed = /*#__PURE__*/ withWasm((wasm, seed: Uint8Array): Uint8Array => {
  wasm.ext_ed_from_seed(8, ...bridge.allocU8a(seed));

  return bridge.resultU8a();
});

export const ed25519Sign = /*#__PURE__*/ withWasm((wasm, pubkey: Uint8Array, seckey: Uint8Array, message: Uint8Array): Uint8Array => {
  wasm.ext_ed_sign(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(seckey), ...bridge.allocU8a(message));

  return bridge.resultU8a();
});

export const ed25519Verify = /*#__PURE__*/ withWasm((wasm, signature: Uint8Array, message: Uint8Array, pubkey: Uint8Array): boolean => {
  const ret = wasm.ext_ed_verify(...bridge.allocU8a(signature), ...bridge.allocU8a(message), ...bridge.allocU8a(pubkey));

  return ret !== 0;
});

export const sr25519DeriveKeypairHard = /*#__PURE__*/ withWasm((wasm, pair: Uint8Array, cc: Uint8Array): Uint8Array => {
  wasm.ext_sr_derive_keypair_hard(8, ...bridge.allocU8a(pair), ...bridge.allocU8a(cc));

  return bridge.resultU8a();
});

export const sr25519DeriveKeypairSoft = /*#__PURE__*/ withWasm((wasm, pair: Uint8Array, cc: Uint8Array): Uint8Array => {
  wasm.ext_sr_derive_keypair_soft(8, ...bridge.allocU8a(pair), ...bridge.allocU8a(cc));

  return bridge.resultU8a();
});

export const sr25519DerivePublicSoft = /*#__PURE__*/ withWasm((wasm, pubkey: Uint8Array, cc: Uint8Array): Uint8Array => {
  wasm.ext_sr_derive_public_soft(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(cc));

  return bridge.resultU8a();
});

export const sr25519KeypairFromSeed = /*#__PURE__*/ withWasm((wasm, seed: Uint8Array): Uint8Array => {
  wasm.ext_sr_from_seed(8, ...bridge.allocU8a(seed));

  return bridge.resultU8a();
});

export const sr25519Sign = /*#__PURE__*/ withWasm((wasm, pubkey: Uint8Array, secret: Uint8Array, message: Uint8Array): Uint8Array => {
  wasm.ext_sr_sign(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(secret), ...bridge.allocU8a(message));

  return bridge.resultU8a();
});

export const sr25519Verify = /*#__PURE__*/ withWasm((wasm, signature: Uint8Array, message: Uint8Array, pubkey: Uint8Array): boolean => {
  const ret = wasm.ext_sr_verify(...bridge.allocU8a(signature), ...bridge.allocU8a(message), ...bridge.allocU8a(pubkey));

  return ret !== 0;
});

export const sr25519Agree = /*#__PURE__*/ withWasm((wasm, pubkey: Uint8Array, secret: Uint8Array): Uint8Array => {
  wasm.ext_sr_agree(8, ...bridge.allocU8a(pubkey), ...bridge.allocU8a(secret));

  return bridge.resultU8a();
});

export function isReady (): boolean {
  return !!bridge.wasm;
}

export async function waitReady (): Promise<boolean> {
  try {
    const wasm = await initBridge();

    return !!wasm;
  } catch {
    return false;
  }
}
