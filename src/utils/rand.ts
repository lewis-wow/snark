import { IField } from '@noble/curves/abstract/modular.js';

export const rand = (fr: IField<bigint>): bigint =>
  fr.fromBytes(crypto.getRandomValues(new Uint8Array(fr.BYTES)));
