import { IField } from '@noble/curves/abstract/modular.js';

export const mulPoly = (
  Fr: IField<bigint>,
  a: bigint[],
  b: bigint[],
): bigint[] => {
  const res = new Array(a.length + b.length - 1).fill(0n);

  for (let i = 0; i < a.length; i++) {
    for (let j = 0; j < b.length; j++) {
      res[i + j] = Fr.add(res[i + j], Fr.mul(a[i], b[j]));
    }
  }

  return res;
};
