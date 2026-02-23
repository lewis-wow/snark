import { IField } from '@noble/curves/abstract/modular.js';

export const rand = (Fr: IField<bigint>): bigint =>
  Fr.fromBytes(crypto.getRandomValues(new Uint8Array(Fr.BYTES)));
