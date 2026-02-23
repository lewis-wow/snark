import { IField } from '@noble/curves/abstract/modular.js';

export const addPoly = (
  Fr: IField<bigint>,
  a: bigint[],
  b: bigint[],
): bigint[] => {
  const maxLen = Math.max(a.length, b.length);
  const res = new Array(maxLen).fill(0n);

  for (let i = 0; i < maxLen; i++) {
    const valA = i < a.length ? a[i] : 0n;
    const valB = i < b.length ? b[i] : 0n;
    res[i] = Fr.add(valA, valB);
  }

  return res;
};
