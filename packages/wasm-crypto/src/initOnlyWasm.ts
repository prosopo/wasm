// Copyright 2019-2022 @polkadot/wasm-crypto authors & contributors
// SPDX-License-Identifier: Apache-2.0

import { setWasmOnlyPromise } from './init';

setWasmOnlyPromise().catch(() => undefined);